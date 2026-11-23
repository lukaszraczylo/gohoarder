import Mathlib

/-!
# Storage keys, path safety, canonicalisation

Models `pkg/cache/cache.go` `generateStorageKey`, `pkg/storage/filesystem/filesystem.go`
`keyToPath`, `pkg/proxy/npm/npm.go` `CanonicalPath`, and `pkg/proxy/pypi/pypi.go`
`extractVersionFromFilename`. Omits: symlinks (the store writes through `os.Root`), Unicode.
-/

namespace Gohoarder.Keys

/-! ### `keyToPath`: segment normalisation -/

/-- `filepath.Clean` plus the strip loop in `keyToPath`: `.` and empty segments vanish, `..` pops
a segment and is dropped at the root. Segments are kept in reverse order. -/
def cleanRev : List String → List String → List String
  | acc, [] => acc
  | acc, seg :: rest =>
    if seg = "." ∨ seg = "" then cleanRev acc rest
    else if seg = ".." then cleanRev acc.tail rest
    else cleanRev (seg :: acc) rest

def clean (segs : List String) : List String := (cleanRev [] segs).reverse

theorem cleanRev_no_dotdot (segs acc : List String) (h : ".." ∉ acc) : ".." ∉ cleanRev acc segs := by
  induction segs generalizing acc with
  | nil => simpa [cleanRev] using h
  | cons seg rest ih =>
    unfold cleanRev
    split_ifs with h1 h2
    · exact ih acc h
    · exact ih acc.tail (fun hm => h (List.mem_of_mem_tail hm))
    · apply ih
      simp only [List.mem_cons, not_or]
      exact ⟨fun e => h2 e.symm, h⟩

/-- No cleaned key contains a `..` segment, so the joined path stays under the store root. -/
theorem clean_stays_in_root (segs : List String) : ".." ∉ clean segs := by
  unfold clean
  simpa using cleanRev_no_dotdot segs [] (by simp)

/-- The sanitiser rewrites; it does not reject. Distinct keys collapse onto one path. -/
theorem keyToPath_not_injective :
    clean ["npm", "pkg", "..", "other", "1.0.0"] = clean ["npm", "other", "1.0.0"] ∧
    ["npm", "pkg", "..", "other", "1.0.0"] ≠ ["npm", "other", "1.0.0"] := by
  decide

theorem keyToPath_traversal_is_clamped :
    clean ["..", "..", "etc", "passwd"] = ["etc", "passwd"] := by decide

/-! ### Key injectivity: `registry/name/version` -/

/-- `generateStorageKey`: join with `/`. -/
def key (registry name version : String) : List String := [registry, name, version]

/-- Over segment lists the tuple is recoverable; `String.intercalate "/"` is injective exactly
when the parts contain no `/`. -/
theorem key_injective (r n v r' n' v' : String) (h : key r n v = key r' n' v') :
    r = r' ∧ n = n' ∧ v = v' := by
  simp only [key, List.cons.injEq, and_true] at h
  exact ⟨h.1, h.2.1, h.2.2⟩

/-- With `/` inside a part the joined string collides: npm `@x/y` + `b` and `@x` + `y/b`. The
second tuple needs an upstream 200 at a path npm never serves, so the proxy cannot store it. -/
theorem joined_key_collides_with_slash :
    String.intercalate "/" ["npm", "@x/y", "b"] = String.intercalate "/" ["npm", "@x", "y/b"] := by
  decide

/-! ### `npm.CanonicalPath`: escaped scope separator -/

inductive Tok | scope | esc | sl | other
  deriving DecidableEq

/-- Rewrites the first escaped `/` of the first segment (`CanonicalPath`'s `strings.Cut`). -/
def rewriteFirst : List Tok → List Tok
  | [] => []
  | Tok.sl :: r => Tok.sl :: r
  | Tok.esc :: r => Tok.sl :: r
  | Tok.scope :: r => Tok.scope :: rewriteFirst r
  | Tok.other :: r => Tok.other :: rewriteFirst r

/-- `CanonicalPath` acts only on a segment starting with `@`. -/
def canon : List Tok → List Tok
  | Tok.scope :: r => Tok.scope :: rewriteFirst r
  | p => p

theorem rewriteFirst_idem (r : List Tok) : rewriteFirst (rewriteFirst r) = rewriteFirst r := by
  induction r with
  | nil => rfl
  | cons t rest ih => cases t <;> simp [rewriteFirst, ih]

/-- Canonicalisation is idempotent: a second pass finds the separator the first one wrote. -/
theorem canon_idem (p : List Tok) : canon (canon p) = canon p := by
  cases p with
  | nil => rfl
  | cons t r => cases t <;> simp [canon, rewriteFirst_idem]

/-- The rewrite adds at most one separator, so a name cannot smuggle extra path segments. -/
theorem rewriteFirst_adds_one_sep (r : List Tok) :
    (rewriteFirst r).count Tok.sl ≤ r.count Tok.sl + 1 := by
  induction r with
  | nil => simp [rewriteFirst]
  | cons t rest ih =>
    cases t <;> simp [rewriteFirst, List.count_cons] at * <;> omega

theorem canon_adds_one_sep (p : List Tok) : (canon p).count Tok.sl ≤ p.count Tok.sl + 1 := by
  cases p with
  | nil => simp [canon]
  | cons t r =>
    have := rewriteFirst_adds_one_sep r
    cases t <;> simp [canon, List.count_cons] at * <;> omega

/-- The escape that survives in the name part (`@a%2fb%2fc` gives `@a/b%2fc`) is later rejected:
Fiber answers 404 to an escaped slash, which `TestNPMScopedNames` and the traversal probe
(`/npm/@s%2fn%2f..%2f..%2fx` returns 404) exercise. -/
theorem canon_keeps_later_escape :
    canon [Tok.scope, Tok.esc, Tok.other, Tok.esc, Tok.other] =
      [Tok.scope, Tok.sl, Tok.other, Tok.esc, Tok.other] := by decide

/-! ### PyPI version from a file name -/

/-- Wheel (PEP 427): the version is the second `-` segment when it starts with a digit. -/
def startsWithDigit (v : String) : Bool :=
  match v.toList with
  | c :: _ => c.isDigit
  | [] => false

def wheelVersion (segs : List String) : Option String :=
  match segs with
  | _ :: v :: _ => if startsWithDigit v then some v else none
  | _ => none

/-- A well-formed wheel name `dist-version-...` yields its version, whatever follows. -/
theorem wheelVersion_correct (d v : String) (rest : List String) (hv : startsWithDigit v = true) :
    wheelVersion (d :: v :: rest) = some v := by
  simp [wheelVersion, hv]

/-- The cache version for a PyPI file is the file name, which is unique per file, while the
release version is shared by all files of a release (`release_version`). Two files of one release
have different keys and one release key: bypasses by release cover both, by design. -/
theorem pypi_key_per_file_release_shared (name f1 f2 : String) (h : f1 ≠ f2) :
    key "pypi" name f1 ≠ key "pypi" name f2 := by
  intro e; exact h (key_injective _ _ _ _ _ _ e).2.2

end Gohoarder.Keys
