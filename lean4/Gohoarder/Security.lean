import Mathlib

/-!
# Security decision logic

Models `pkg/scanner/scanner.go` `CheckVulnerabilities`, `scan`, `mergeResults`, `scheduleRetry`,
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

/-! ### Merge: worst status wins, but a failed scanner leaves no trace -/

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

/-- Results exist only for scanners that returned; with one scanner failing and one clean, the
merged status is clean and no retry is scheduled (`scan`: retry only when no scanner succeeded). -/
theorem partial_failure_reads_clean : mergeRank [0] = 0 := by decide

end Gohoarder.Security
