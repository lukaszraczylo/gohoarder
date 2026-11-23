import Mathlib

/-!
# Access control and upstream fetch guards

Models `pkg/app/app.go` `buildCheckOrigin` / `normalizeOriginHost`, `pkg/app/handlers_admin.go`
`requireAdmin`, `pkg/auth/auth.go` (`getPermissionsForRole`, `ValidateAPIKey` expiry),
`pkg/proxy/pypi/pypi.go` (`isAllowedPyPIHost`, the `original_url` guards), `Dockerfile.frontend`.
Omits: the TLS layer, bcrypt internals, DNS.
-/

namespace Gohoarder.Access

/-! ### WebSocket origin -/

inductive Scheme | http | https
  deriving DecidableEq

def defaultPort : Scheme → ℕ
  | Scheme.http => 80
  | Scheme.https => 443

/-- An origin after `strings.ToLower`: host labels plus an optional explicit port. -/
structure Origin where
  scheme : Scheme
  host : List Char
  port : Option ℕ

/-- `normalizeOriginHost`: a port equal to the scheme default is dropped; compare on the effective port. -/
def effPort (o : Origin) : ℕ := o.port.getD (defaultPort o.scheme)

/-- An exact allowlist rule matches iff scheme, host and effective port agree (`buildCheckOrigin`). -/
def matchesExact (rule o : Origin) : Bool :=
  decide (rule.scheme = o.scheme) && decide (rule.host = o.host) && decide (effPort rule = effPort o)

theorem default_port_equivalent (s : Scheme) (h : List Char) :
    matchesExact ⟨s, h, none⟩ ⟨s, h, some (defaultPort s)⟩ = true := by
  simp [matchesExact, effPort]

theorem scheme_mismatch_rejected (rule o : Origin) (h : rule.scheme ≠ o.scheme) :
    matchesExact rule o = false := by
  simp [matchesExact, h]

theorem port_mismatch_rejected (s : Scheme) (h : List Char) (p q : ℕ) (hp : p ≠ q) :
    matchesExact ⟨s, h, some p⟩ ⟨s, h, some q⟩ = false := by
  simp [matchesExact, effPort, hp]

/-- Wildcard rule `https://*.d`: `strings.HasSuffix(host, ".d")` or host = `d`. -/
def matchesGlob (d host : List Char) : Bool :=
  decide (host = d) || decide (('.' :: d) <:+ host)

/-- The leading dot pins the match to a label boundary: `evilexample.com` is not under `example.com`. -/
theorem glob_rejects_label_prefix :
    matchesGlob "example.com".toList "evilexample.com".toList = false := by decide

theorem glob_accepts_subdomain :
    matchesGlob "example.com".toList "app.example.com".toList = true := by decide

theorem glob_rejects_suffix_trick :
    matchesGlob "example.com".toList "example.com.evil.net".toList = false := by decide

/-! ### Admin gate -/

inductive Role | readonly | readwrite | admin
  deriving DecidableEq

/-- `getPermissionsForRole`, restricted to the bypass-management and key-management permissions. -/
def canManageBypasses : Role → Bool
  | Role.admin => true
  | _ => false

def canManageKeys : Role → Bool
  | Role.admin => true
  | _ => false

/-- `requireAdmin` admits a key with the admin role or the `bypasses:manage` permission; it also
guards `/api/admin/keys`. No other role holds that permission, so no escalation to key minting. -/
def requireAdminPasses (r : Role) : Bool := decide (r = Role.admin) || canManageBypasses r

theorem admin_gate_implies_key_manager (r : Role) (h : requireAdminPasses r = true) :
    canManageKeys r = true := by
  cases r <;> simp_all [requireAdminPasses, canManageBypasses, canManageKeys]

/-- `ValidateAPIKey`: a key is a candidate iff it has no expiry or `now <= expiresAt`. -/
def keyLive (now : ℤ) (exp : Option ℤ) : Bool :=
  match exp with
  | none => true
  | some e => decide (now ≤ e)

theorem expired_key_rejected (now e : ℤ) (h : e < now) : keyLive now (some e) = false := by
  simp [keyLive, not_le.mpr h]

/-! ### PyPI `original_url` guards -/

/-- A fetch the handler would perform: host and file name of `original_url`. -/
structure Fetch where
  host : String
  file : String

def allowedHosts : List String := ["pypi.org", "files.pythonhosted.org", "pythonhosted.org"]

/-- `isAllowedPyPIHost`: listed hosts, or a subdomain of pythonhosted.org (suffix on characters). -/
def hostAllowed (h : String) : Bool :=
  decide (h ∈ allowedHosts) || decide (".pythonhosted.org".toList <:+ h.toList)

/-- Before the fix: host allowlist only. The cache key is `pypi/<name>/<requested file>`. -/
def acceptsOld (f : Fetch) : Bool := hostAllowed f.host

/-- After the fix: the fetched file must be the requested one. -/
def acceptsNew (requested : String) (f : Fetch) : Bool := hostAllowed f.host && decide (f.file = requested)

/-- Integrity of the cache key: what is stored under a key is the file the key names. -/
theorem fixed_guard_binds_key (requested : String) (f : Fetch) (h : acceptsNew requested f = true) :
    f.file = requested := by
  simp only [acceptsNew, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.2

/-- Before the fix any file on an allowed host was stored under any requested name. -/
theorem old_guard_allows_key_poisoning :
    ∃ requested f, acceptsOld f = true ∧ f.file ≠ requested := by
  exact ⟨"requests-2.31.0-py3-none-any.whl", ⟨"files.pythonhosted.org", "evil-9.9.9-py3-none-any.whl"⟩,
    by decide, by decide⟩

theorem internal_hosts_rejected :
    hostAllowed "169.254.169.254" = false ∧ hostAllowed "localhost" = false ∧
    hostAllowed "metadata.google.internal" = false := by decide

/-- The allowlist is checked once, on the first hop. `network.Client` follows redirects without
re-checking, so an allowed host that answers 302 reaches any target. Acceptable only while no
allowed host redirects (pypi.org and files.pythonhosted.org do not). -/
def hopAllowed (hops : List String) : Bool := hops.head?.any hostAllowed

theorem redirect_escapes_allowlist :
    hopAllowed ["files.pythonhosted.org", "169.254.169.254"] = true ∧
    hostAllowed "169.254.169.254" = false := by decide

/-! ### Frontend blocklist (`Dockerfile.frontend`) -/

/-- `location ~ ^/(npm|pypi|go|metrics)(/|$)` on the normalised URI. -/
def blocked (first : String) (rest : String) : Bool :=
  decide (first ∈ ["npm", "pypi", "go", "metrics"]) && (decide (rest.toList = []) || decide (rest.toList.head? = some '/'))

theorem blocklist_covers_registries :
    blocked "npm" "/x" = true ∧ blocked "pypi" "" = true ∧ blocked "go" "/@v/list" = true ∧
    blocked "metrics" "" = true := by decide

/-- A prefix that merely starts with a registry name is not blocked, and is not proxied either: the
`/health` and `/api/` locations are the only ones with a backend. -/
theorem blocklist_is_segment_exact : blocked "npmx" "" = false := by decide

end Gohoarder.Access
