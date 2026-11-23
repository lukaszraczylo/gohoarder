import Mathlib

/-!
# Cache lifecycle

Models `pkg/cache/cache.go`: `store` (expiry), `getOrFetch` and `Get` (hit path,
retry), `purge` and `cleanup` (idle eviction), `evict` (LRU).
What it omits: wall-clock skew, the storage backend, byte-level I/O.
-/

namespace Gohoarder.Cache

/-! ### Expiry: artifacts never expire by age, metadata pages do -/

/-- `pkg/cache/cache.go` `store`: only metadata entries get `now + DefaultTTL`. -/
def expiryFor (isMeta : Bool) (now ttl : ℤ) : Option ℤ :=
  if isMeta then some (now + ttl) else none

/-- `pkg/cache/cache.go` `getOrFetch`: `pkg.ExpiresAt != nil && m.now().After(*pkg.ExpiresAt)`. -/
def expired (e : Option ℤ) (now : ℤ) : Prop := ∃ x, e = some x ∧ x < now

theorem artifact_never_expires (now ttl t : ℤ) : ¬ expired (expiryFor false now ttl) t := by
  simp [expiryFor, expired]

theorem metadata_expires_after_ttl (now ttl t : ℤ) (h : now + ttl < t) :
    expired (expiryFor true now ttl) t :=
  ⟨now + ttl, by simp [expiryFor], h⟩

theorem metadata_fresh_within_ttl (now ttl t : ℤ) (h : t ≤ now + ttl) :
    ¬ expired (expiryFor true now ttl) t := by
  simp only [expired, expiryFor, ite_true, Option.some.injEq, exists_eq_left']
  omega

/-! ### Idle eviction -/

/-- `pkg/cache/cache.go` `cleanup`: cutoff = now - IdleTTL; due iff `LastAccessed.Before(cutoff)`. -/
def idleDue (now idleTTL lastAccessed : ℤ) : Prop := lastAccessed < now - idleTTL

theorem idle_keeps_recent (now idleTTL la : ℤ) (h : now - la ≤ idleTTL) :
    ¬ idleDue now idleTTL la := by
  unfold idleDue; omega

theorem idle_removes_stale (now idleTTL la : ℤ) (h : idleTTL < now - la) :
    idleDue now idleTTL la := by
  unfold idleDue; omega

/-- A request refreshes `LastAccessed` (`UpdateDownloadCount`), so a hit is never idle-due at that instant. -/
theorem touch_defers_idle (now idleTTL : ℤ) (h : 0 ≤ idleTTL) : ¬ idleDue now idleTTL now := by
  unfold idleDue; omega

/-! ### Interleavings of a hit and a purge -/

/-- One step of the concurrent schedule on a single entry. -/
inductive Step
  | touch (t : ℤ)   -- a request refreshes LastAccessed
  | check           -- purge's `stillDue` re-read
  | del             -- purge's `deletePackage`
  deriving DecidableEq

structure World where
  last : ℤ
  present : Bool
  checked : Bool   -- the last `check` found the entry due
  deriving DecidableEq

def run (cutoff : ℤ) : World → List Step → World
  | w, [] => w
  | w, Step.touch t :: s => run cutoff { w with last := t } s
  | w, Step.check :: s => run cutoff { w with checked := decide (w.last < cutoff) } s
  | w, Step.del :: s => run cutoff { w with present := if w.checked then false else w.present } s

/-- Check and delete are two steps (`purge`: `stillDue(current)` then `deletePackage`), so a
request between them is lost: the entry is deleted although `LastAccessed >= cutoff`. This is
the window `Get` now covers with its retry. -/
theorem purge_window_deletes_fresh_entry :
    let w := run 10 ⟨0, true, false⟩ [Step.check, Step.touch 20, Step.del]
    w.present = false ∧ 10 ≤ w.last := by
  decide

/-- With no request inside the window the purge honours `stillDue`. -/
theorem purge_without_window_keeps_fresh (cutoff t : ℤ) (h : cutoff ≤ t) :
    (run cutoff ⟨0, true, false⟩ [Step.touch t, Step.check, Step.del]).present = true := by
  simp [run, not_lt.mpr h]

/-! ### `Get`: probe, then open -/

inductive Outcome | served | refetched | error
  deriving DecidableEq

/-- Before the fix: probe in `getOrFetch`, open after the singleflight; `purgedBetween` is a delete
between the two. -/
def getOnce (present purgedBetween : Bool) : Outcome :=
  if present then (if purgedBetween then Outcome.error else Outcome.served) else Outcome.refetched

/-- `Get` with `getAttempts = 2`: the second pass re-probes the (now missing) blob and fetches. -/
def getRetry (present d1 d2 : Bool) : Outcome :=
  match getOnce present d1 with
  | Outcome.error => if d2 then Outcome.error else Outcome.refetched
  | o => o

theorem getOnce_errors_on_purge : getOnce true true = Outcome.error := rfl

/-- At most one purge per `Get` never reaches the client as an error. -/
theorem getRetry_survives_one_purge (present d1 d2 : Bool) (h : ¬ (d1 = true ∧ d2 = true)) :
    getRetry present d1 d2 ≠ Outcome.error := by
  cases present <;> cases d1 <;> cases d2 <;> simp_all [getRetry, getOnce]

/-! ### LRU eviction -/

/-- `evict`: delete oldest first until `freed >= needed`; `sizes` is the oldest-first listing. -/
def evictFreed : List ℕ → ℕ → ℕ
  | [], _ => 0
  | s :: rest, needed => if needed = 0 then 0 else s + evictFreed rest (needed - s)

theorem evictFreed_le_total (sizes : List ℕ) (needed : ℕ) : evictFreed sizes needed ≤ sizes.sum := by
  induction sizes generalizing needed with
  | nil => simp [evictFreed]
  | cons s rest ih =>
    unfold evictFreed
    split_ifs
    · simp
    · simp only [List.sum_cons]; have := ih (needed - s); omega

theorem evictFreed_ge (sizes : List ℕ) (needed : ℕ) (h : needed ≤ sizes.sum) :
    needed ≤ evictFreed sizes needed := by
  induction sizes generalizing needed with
  | nil => simpa [evictFreed] using h
  | cons s rest ih =>
    unfold evictFreed
    split_ifs with h0
    · omega
    · simp only [List.sum_cons] at h
      have := ih (needed - s) (by omega)
      omega

/-- After `store` evicts for `needed = used + size - limit` and the listing held enough bytes,
usage including the new entry is within the cap. -/
theorem lru_keeps_cap (used size limit : ℕ) (sizes : List ℕ)
    (hroom : used + size - limit ≤ sizes.sum) :
    used + size - evictFreed sizes (used + size - limit) ≤ limit := by
  have h1 := evictFreed_ge sizes (used + size - limit) hroom
  omega

/-- When the listing cannot free enough (`freed < needed`) `evict` still returns nil, so the cap
rests on the backend's `Put` quota check (`filesystem.go` `Put`). The hypothesis of `lru_keeps_cap`
fails here, and the result exceeds the cap. -/
theorem lru_cap_needs_enough_evictable :
    ∃ used size limit : ℕ, ∃ sizes : List ℕ,
      used + size - evictFreed sizes (used + size - limit) > limit := by
  exact ⟨100, 10, 100, [5], by decide⟩

/-- The entry being stored is not in the metadata listing (`SavePackage` runs after `Put`), so
eviction never deletes it. -/
theorem evict_spares_unlisted (listed : List String) (new : String) (h : new ∉ listed) :
    ∀ victim ∈ listed.take 100, victim ≠ new := by
  intro v hv hv'
  exact h (hv' ▸ List.mem_of_mem_take hv)

/-- One eviction pass: `n` listed rows of which `d` can be deleted; the rest are listed again. -/
def passRemaining (n d : ℕ) : ℕ := n - d

/-- Before the fix the loop continued on `n >= limit` only; a pass that deletes nothing re-lists
the same rows and never ends. -/
theorem old_evict_is_stuck (n : ℕ) : passRemaining n 0 = n := by simp [passRemaining]

/-- After the fix a pass continues only if it deleted a row, so the row count strictly falls. -/
theorem fixed_evict_measure_falls (n d : ℕ) (hd : 0 < d) (hdn : d ≤ n) : passRemaining n d < n := by
  unfold passRemaining; omega

/-! ### Quota accounting: overwriting a key

`pkg/storage/filesystem/filesystem.go` `Put`: `fs.used` tracks bytes on disk. -/

/-- After the fix: an overwrite releases the bytes of the file it replaces. -/
def usedAfterPut (used replaced written : ℕ) : ℕ := used - replaced + written

/-- Before the fix: the replaced bytes stayed counted. -/
def usedAfterPutOld (used written : ℕ) : ℕ := used + written

/-- If `used` is the sum of the stored sizes, `other + replaced`, the counter stays exact. -/
theorem put_keeps_usage_exact (other replaced written : ℕ) :
    usedAfterPut (other + replaced) replaced written = other + written := by
  unfold usedAfterPut; omega

/-- Two writes of one key (400 then 300 bytes) leave 700 counted, 300 on disk. -/
theorem old_put_inflates_usage : usedAfterPutOld (usedAfterPutOld 0 400) 300 = 700 ∧
    usedAfterPut (usedAfterPut 0 0 400) 400 300 = 300 := by decide

/-! ### Which entries skip the scan

`pkg/metadata/interface.go` `IsMetadataEntry`; the scan gate in `getOrFetch` and `store`. -/

def metaVersions : List String := ["list", "page", "latest", "metadata"]

/-- After the fix the `.mod` / `.info` name suffix exempts Go entries only. -/
def scanExempt (registry : String) (nameSuffixMeta : Bool) (version : String) : Bool :=
  decide (version ∈ metaVersions) || (decide (registry = "go") && nameSuffixMeta)

/-- Before the fix the suffix exempted any registry. -/
def scanExemptOld (nameSuffixMeta : Bool) (version : String) : Bool :=
  decide (version ∈ metaVersions) || nameSuffixMeta

theorem npm_named_like_go_metadata_is_scanned (v : String) (hv : v ∉ metaVersions) :
    scanExempt "npm" true v = false := by
  simp [scanExempt, hv]

theorem old_exempted_npm_package : scanExemptOld true "1.0.0" = true := by decide

theorem go_metadata_still_exempt : scanExempt "go" true "v1.0.0" = true := by decide

/-- `pkg/scanner/rescanner.go` before the fix: the worker skipped only the version names, not the Go suffixes. -/
def rescanSkipOld (version : String) : Bool := decide (version ∈ metaVersions)

/-- After the fix the worker asks `IsMetadataEntry`, the same predicate as the serve path. -/
def rescanSkip : String → Bool → String → Bool := scanExempt

theorem old_rescan_scanned_go_metadata :
    rescanSkipOld "v1.0.0" = false ∧ scanExempt "go" true "v1.0.0" = true := by decide

theorem rescan_skips_what_serve_skips (registry : String) (suffixMeta : Bool) (version : String) :
    rescanSkip registry suffixMeta version = scanExempt registry suffixMeta version := rfl

end Gohoarder.Cache
