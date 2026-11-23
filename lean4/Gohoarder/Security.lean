import Mathlib

/-!
# Security decision logic

Models `pkg/scanner/scanner.go` `CheckVulnerabilities`, `scan`, `mergeResults`, `succeeded`, `scheduleRetry`,
`pkg/metadata/gormstore/gormstore_v2.go` `GetActiveCVEBypasses`, and the scan gate in
`pkg/cache/cache.go` `getOrFetch`. Severities are ranks (low 1 .. critical 4). Omits: the
scanners themselves, threshold counters (`block_thresholds`), network.
-/

namespace Gohoarder.Security

structure Vuln where
  id : ℕ
  sev : ℕ

structure Bypass where
  cve : ℕ
  covers : Bool      -- `AppliesTo` empty or equal to this package
  active : Bool
  expiresAt : ℤ

/-- `GetActiveCVEBypasses`: `active = true AND expires_at > now`. -/
def activeAt (now : ℤ) (b : Bypass) : Bool := b.active && decide (now < b.expiresAt)

def bypassedIds (now : ℤ) (bs : List Bypass) : List ℕ :=
  (bs.filter fun b => activeAt now b && b.covers).map (·.cve)

/-- The vulnerabilities no bypass covers (`severityCounts` loop). -/
def remaining (now : ℤ) (bs : List Bypass) (vs : List Vuln) : List Vuln :=
  vs.filter fun v => decide (v.id ∉ bypassedIds now bs)

/-- `block_on_severity`: `none` for "none"/empty, else block when a remaining vulnerability has
rank at or above the threshold. -/
def blocksBySeverity (policy : Option ℕ) (vs : List Vuln) : Bool :=
  match policy with
  | none => false
  | some t => vs.any fun v => decide (t ≤ v.sev)

def decideSev (policy : Option ℕ) (now : ℤ) (bs : List Bypass) (vs : List Vuln) : Bool :=
  blocksBySeverity policy (remaining now bs vs)

/-- The LOW branch before the fix: `len(result.Vulnerabilities) > 0`, bypasses ignored. -/
def decideLowOld (vs : List Vuln) : Bool := decide (0 < vs.length)

theorem expired_bypass_inactive (now : ℤ) (b : Bypass) (h : b.expiresAt ≤ now) : activeAt now b = false := by
  simp [activeAt, not_lt.mpr h]

theorem inactive_bypass_ignored (now : ℤ) (b : Bypass) (h : b.active = false) : activeAt now b = false := by
  simp [activeAt, h]

/-- Every vulnerability bypassed by an active, covering bypass: nothing blocks, for any policy. -/
theorem fully_bypassed_never_blocks (policy : Option ℕ) (now : ℤ) (bs : List Bypass) (vs : List Vuln)
    (h : ∀ v ∈ vs, v.id ∈ bypassedIds now bs) : decideSev policy now bs vs = false := by
  have : remaining now bs vs = [] := by
    simp only [remaining, List.filter_eq_nil_iff, decide_eq_true_eq, not_not]
    exact h
  simp [decideSev, this, blocksBySeverity]
  cases policy <;> simp

/-- A vulnerability at or above the policy that no active bypass covers blocks. -/
theorem uncovered_vuln_blocks (t : ℕ) (now : ℤ) (bs : List Bypass) (vs : List Vuln) (v : Vuln)
    (hv : v ∈ vs) (hsev : t ≤ v.sev) (hun : v.id ∉ bypassedIds now bs) :
    decideSev (some t) now bs vs = true := by
  simp only [decideSev, blocksBySeverity, List.any_eq_true, decide_eq_true_eq]
  refine ⟨v, ?_, hsev⟩
  simp [remaining, hv, hun]

/-- Adding a bypass never turns an allow into a block. -/
theorem bypass_monotone (policy : Option ℕ) (now : ℤ) (b : Bypass) (bs : List Bypass) (vs : List Vuln)
    (h : decideSev policy now (b :: bs) vs = true) : decideSev policy now bs vs = true := by
  cases policy with
  | none => simp [decideSev, blocksBySeverity] at h
  | some t =>
    simp only [decideSev, blocksBySeverity, List.any_eq_true, decide_eq_true_eq, remaining,
      List.mem_filter] at h ⊢
    obtain ⟨v, ⟨hv, hn⟩, hs⟩ := h
    refine ⟨v, ⟨hv, ?_⟩, hs⟩
    intro hmem
    apply hn
    simp only [bypassedIds, List.filter_cons] at hmem ⊢
    split_ifs <;> simp_all

/-- Before the fix, LOW blocked a package whose only vulnerability was bypassed. -/
theorem old_low_ignores_bypass :
    let vs := [Vuln.mk 1 1]
    let bs := [Bypass.mk 1 true true 100]
    decideLowOld vs = true ∧ decideSev (some 1) 0 bs vs = false := by
  decide

/-! ### Serve decision -/

inductive Scan
  | missing (inflight : Bool)   -- no result row; `isInflight` while a scan runs
  | err (infra : Bool)          -- every scanner failed
  | ok (vs : List Vuln)

/-- `CheckVulnerabilities` and the gate: `true` means the package is served. -/
def serves (failClosed pkgBypass : Bool) (policy : Option ℕ) (now : ℤ) (bs : List Bypass) :
    Scan → Bool
  | s =>
    if pkgBypass then true else
    match s with
    | Scan.missing inflight => !failClosed && inflight
    | Scan.err infra => !failClosed && infra
    | Scan.ok vs => !decideSev policy now bs vs

theorem fail_closed_blocks_without_verdict (policy : Option ℕ) (now : ℤ) (bs : List Bypass) (s : Scan)
    (hs : (∃ i, s = Scan.missing i) ∨ (∃ i, s = Scan.err i)) :
    serves true false policy now bs s = false := by
  rcases hs with ⟨i, rfl⟩ | ⟨i, rfl⟩ <;> simp [serves]

/-- A vulnerable package is not served when policy blocks, unless a package bypass covers it. -/
theorem vulnerable_not_served (policy : Option ℕ) (t : ℕ) (hp : policy = some t) (failClosed : Bool)
    (now : ℤ) (bs : List Bypass) (vs : List Vuln) (v : Vuln) (hv : v ∈ vs) (hsev : t ≤ v.sev)
    (hun : v.id ∉ bypassedIds now bs) :
    serves failClosed false policy now bs (Scan.ok vs) = false := by
  subst hp
  simp [serves, uncovered_vuln_blocks t now bs vs v hv hsev hun]

/-- With `fail_closed = false`, exactly these states serve a package with no verdict: a scan in
flight, or every scanner failing on infrastructure. A package bypass serves in any state. -/
theorem unscanned_served_iff (failClosed pkgBypass : Bool) (policy : Option ℕ) (now : ℤ)
    (bs : List Bypass) (i : Bool) :
    (serves failClosed pkgBypass policy now bs (Scan.missing i) = true ↔
        pkgBypass = true ∨ (failClosed = false ∧ i = true)) ∧
    (serves failClosed pkgBypass policy now bs (Scan.err i) = true ↔
        pkgBypass = true ∨ (failClosed = false ∧ i = true)) := by
  cases failClosed <;> cases pkgBypass <;> cases i <;> simp [serves]

/-- The infra-error record never changes with retries, so the package stays served. -/
theorem infra_error_served_forever (policy : Option ℕ) (now : ℤ) (bs : List Bypass) :
    serves false false policy now bs (Scan.err true) = true := by
  simp [serves]

/-- Scanner disabled: `CheckVulnerabilities` returns `(false, "", nil)` and `cache.New` drops the scanner. -/
def servesDisabled : Bool := true

/-! ### Retry input (`pkg/cache/cache.go` `store`, `ScanFile`; `scheduleRetry`) -/

/-- Before the fix a retry reused the first scan's path. Remote storage scans a temp file removed
after the first attempt, so only local backends kept it. -/
def retryReadableOld (localBackend : Bool) : Bool := localBackend

/-- After the fix a retry whose file is gone re-reads the blob through the file source. -/
def retryReadableNew (localBackend fileSourceSet : Bool) : Bool := localBackend || fileSourceSet

theorem old_remote_retry_unreadable : retryReadableOld false = false := rfl

theorem fixed_retry_always_readable : retryReadableNew false true = true ∧ retryReadableNew true false = true := by
  decide

/-! ### Retry budget -/

def maxRetries : ℕ := 6
def retryIntervalMin : ℕ := 5

/-- Scans run from `attempt`: `scan` schedules attempt+1 only when infra-only and `attempt < maxRetries`. -/
def scansFrom : ℕ → ℕ
  | 0 => 1
  | k + 1 => 1 + scansFrom k

theorem scansFrom_eq (k : ℕ) : scansFrom k = k + 1 := by
  induction k with
  | zero => rfl
  | succ k ih => simp only [scansFrom, ih]; omega

theorem scans_total : scansFrom maxRetries = maxRetries + 1 := scansFrom_eq _

theorem retry_window_minutes : maxRetries * retryIntervalMin = 30 := by decide

/-- The attempt counter is bounded, so a package that keeps failing on infrastructure is scanned at most 7 times. -/
theorem retry_terminates (attempt : ℕ) : scansFrom (maxRetries - attempt) ≤ maxRetries + 1 := by
  rw [scansFrom_eq]; omega

/-! ### Which version scanners are asked about

`pkg/scanner/scanner.go` `scanVersion`: PyPI artifacts are cached under their file name. -/

def scanVersion (release cacheVersion : String) : String :=
  if release = "" then cacheVersion else release

theorem scan_asks_release_version (release cacheVersion : String) (h : release ≠ "") :
    scanVersion release cacheVersion = release := by
  simp [scanVersion, h]

theorem npm_scan_keeps_cache_version (cacheVersion : String) :
    scanVersion "" cacheVersion = cacheVersion := by
  simp [scanVersion]

/-- Before the fix scanners received the file name, which is never a release version. -/
theorem file_name_is_not_release_version :
    "requests-2.19.0-py3-none-any.whl" ≠ "2.19.0" := by decide

/-! ### Merge: worst status wins among scanners that ran; a failed scanner leaves no trace -/

/-- ranks: clean 0, pending 1, error 2, vulnerable 3 (`mergeResults`). -/
def mergeRank (xs : List ℕ) : ℕ := xs.foldr max 0

theorem merge_dominates (xs : List ℕ) (x : ℕ) (h : x ∈ xs) : x ≤ mergeRank xs := by
  induction xs with
  | nil => simp at h
  | cons y ys ih =>
    simp only [mergeRank, List.foldr_cons]
    rcases List.mem_cons.mp h with rfl | h
    · exact le_max_left _ _
    · exact le_trans (ih h) (le_max_right _ _)

def errorRank : ℕ := 2

/-- Before GH-25 a scanner's error-status result took part in the merge, as the rank `errorRank`. -/
def oldMerge (xs : List ℕ) : ℕ := mergeRank xs

/-- `scan` after GH-25: a scanner that returns an error-status result failed, like one that returns
an error. Only results of scanners that ran are merged; with none left every scanner failed. -/
def newMerge (xs : List ℕ) : ℕ :=
  if (xs.filter (· ≠ errorRank)).isEmpty then errorRank else mergeRank (xs.filter (· ≠ errorRank))

/-- GH-25: one scanner's error result turned a clean package into an error row. -/
theorem old_error_poisons_clean : oldMerge [0, errorRank] = errorRank := by decide

theorem error_and_clean_reads_clean : newMerge [0, errorRank] = 0 := by decide

theorem error_never_hides_vulnerable : newMerge [errorRank, 3] = 3 := by decide

theorem all_error_reads_error (xs : List ℕ) (h : ∀ x ∈ xs, x = errorRank) : newMerge xs = errorRank := by
  have : xs.filter (· ≠ errorRank) = [] := by
    rw [List.filter_eq_nil_iff]
    intro x hx
    simp [h x hx]
  unfold newMerge
  rw [this]
  rfl

theorem error_result_ignored (xs : List ℕ) : newMerge (errorRank :: xs) = newMerge xs := by
  simp [newMerge]

theorem mergeRank_not_error (ys : List ℕ) (h : ∀ y ∈ ys, y ≠ errorRank) : mergeRank ys ≠ errorRank := by
  induction ys with
  | nil => simp [mergeRank, errorRank]
  | cons y ys ih =>
    simp only [mergeRank, List.foldr_cons]
    have hy : y ≠ errorRank := h y (List.mem_cons_self ..)
    have hys : mergeRank ys ≠ errorRank := ih (fun z hz => h z (List.mem_cons_of_mem _ hz))
    rcases max_choice y (ys.foldr max 0) with e | e
    · rw [e]; exact hy
    · rw [e]; exact hys

/-- With any scanner that ran, the merged status is not an error, so `fail_closed` never decides it. -/
theorem merged_not_error_when_one_ran (xs : List ℕ) (h : ∃ x ∈ xs, x ≠ errorRank) :
    newMerge xs ≠ errorRank := by
  obtain ⟨x, hx, hne⟩ := h
  have hmem : x ∈ xs.filter (· ≠ errorRank) := List.mem_filter.mpr ⟨hx, by simpa using hne⟩
  unfold newMerge
  have hne' : ¬ (xs.filter (· ≠ errorRank)).isEmpty = true := by
    intro hempty
    rw [List.isEmpty_iff] at hempty
    rw [hempty] at hmem
    simp at hmem
  simp only [hne']
  apply mergeRank_not_error
  intro y hy
  simpa using (List.mem_filter.mp hy).2

/-- The retry is for infrastructure only: `scan` counts each failure by cause and the row is an
infrastructure error only when there was a failure and every failure was infrastructure. -/
def infraOnly (failures : List Bool) : Bool := decide (failures ≠ []) && failures.all id

theorem one_package_failure_is_not_infra : infraOnly [true, false] = false := by decide

theorem all_infra_failures_are_infra : infraOnly [true, true] = true := by decide

/-! ### Rescan on access (`pkg/cache/rescan_on_access.go` `refreshStaleScan`)

Ages are seconds since `ScannedAt`; `interval` is `Config.RescanAfter` (0 = off). A rescan that timed out
or failed is `none`: the previous verdict stands, and with no previous verdict the first-download rule applies. -/

structure Verdict where
  scan : Scan
  age : ℕ

/-- The hit is rescanned when the feature is on and its result is missing or at least `interval` old. -/
def rescans (interval : ℕ) (prev : Option Verdict) : Bool :=
  decide (0 < interval) && (match prev with
    | none => true
    | some v => decide (interval ≤ v.age))

/-- The verdict the gate decides on; a finished rescan is brand new (age 0). -/
def hitVerdict (interval : ℕ) (prev : Option Verdict) (rescan : Option Scan) : Option Verdict :=
  if rescans interval prev then
    (match rescan with
      | some s => some ⟨s, 0⟩
      | none => prev)
  else prev

/-- No verdict at all is a scan still in flight: `fail_closed` refuses, otherwise the package is served. -/
def servesOnAccess (failClosed pkgBypass : Bool) (policy : Option ℕ) (now : ℤ) (bs : List Bypass)
    (interval : ℕ) (prev : Option Verdict) (rescan : Option Scan) : Bool :=
  match hitVerdict interval prev rescan with
  | some v => serves failClosed pkgBypass policy now bs v.scan
  | none => serves failClosed pkgBypass policy now bs (Scan.missing true)

/-- Key property: with the feature on, a rescan that finished leaves no verdict as old as `interval`. -/
theorem finished_rescan_verdict_younger_than_interval (interval : ℕ) (hi : 0 < interval)
    (prev : Option Verdict) (s : Scan) (v : Verdict)
    (h : hitVerdict interval prev (some s) = some v) : v.age < interval := by
  unfold hitVerdict at h
  by_cases hr : rescans interval prev = true
  · simp only [hr, ite_true, Option.some.injEq] at h
    subst h
    simpa using hi
  · simp only [hr] at h
    subst h
    simp only [rescans, hi, decide_true, Bool.true_and, Bool.not_eq_true] at hr
    simpa using hr

/-- A verdict older than `interval` survives only when the rescan timed out or failed. -/
theorem old_verdict_only_on_timeout (interval : ℕ) (hi : 0 < interval) (prev : Option Verdict)
    (rescan : Option Scan) (v : Verdict) (h : hitVerdict interval prev rescan = some v)
    (hold : interval ≤ v.age) : rescan = none := by
  cases rescan with
  | none => rfl
  | some s => exact absurd (finished_rescan_verdict_younger_than_interval interval hi prev s v h) (not_lt.mpr hold)

/-- A stale hit is judged on the fresh scan: a clean result that now holds a blocked vulnerability is refused. -/
theorem stale_clean_fresh_vulnerable_blocked (policy : Option ℕ) (t : ℕ) (hp : policy = some t)
    (failClosed : Bool) (now : ℤ) (bs : List Bypass) (interval age : ℕ) (hi : 0 < interval)
    (hage : interval ≤ age) (vs : List Vuln) (v : Vuln) (hv : v ∈ vs) (hsev : t ≤ v.sev)
    (hun : v.id ∉ bypassedIds now bs) :
    servesOnAccess failClosed false policy now bs interval (some ⟨Scan.ok [], age⟩) (some (Scan.ok vs)) = false := by
  have hr : rescans interval (some ⟨Scan.ok [], age⟩) = true := by simp [rescans, hi, hage]
  simp only [servesOnAccess, hitVerdict, hr, ite_true]
  exact vulnerable_not_served policy t hp failClosed now bs vs v hv hsev hun

/-- A fresh result is served as is: no rescan, whatever the rescan outcome. -/
theorem fresh_hit_not_rescanned (interval : ℕ) (v : Verdict) (hfresh : v.age < interval)
    (rescan : Option Scan) : hitVerdict interval (some v) rescan = some v := by
  have : rescans interval (some v) = false := by simp [rescans, not_le.mpr hfresh]
  simp [hitVerdict, this]

/-- A timeout keeps the previous verdict. -/
theorem timeout_keeps_previous (interval : ℕ) (prev : Option Verdict) :
    hitVerdict interval prev none = prev := by
  unfold hitVerdict
  split <;> rfl

/-- A timeout with no previous verdict follows the first-download rule. -/
theorem timeout_without_previous_is_miss_rule (failClosed pkgBypass : Bool) (policy : Option ℕ) (now : ℤ)
    (bs : List Bypass) (interval : ℕ) :
    servesOnAccess failClosed pkgBypass policy now bs interval none none = (pkgBypass || !failClosed) := by
  simp only [servesOnAccess, timeout_keeps_previous]
  cases failClosed <;> cases pkgBypass <;> simp [serves]

/-- `rescan_on_access` off (`RescanAfter` 0) is the old hit path: the stored verdict decides. -/
theorem off_is_old_hit_path (prev : Option Verdict) (rescan : Option Scan) :
    hitVerdict 0 prev rescan = prev := by
  simp [hitVerdict, rescans]

end Gohoarder.Security
