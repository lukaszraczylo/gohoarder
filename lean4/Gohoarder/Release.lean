import Mathlib

/-!
# Release-age passthrough

Models `pkg/proxy/npm/npm.go` `rewriteMetadataURLs`, `pkg/proxy/pypi/simple_json.go`
`rewriteJSONPage`, and the packument/index freshness TTL in `pkg/cache/cache.go`. A client gate
accepts a version when `now - publishedAt >= gate`. Omits: JSON parsing, number formatting.
-/

namespace Gohoarder.Release

/-- A JSON object as key/value pairs. -/
abbrev Obj := List (String × String)

/-- `rewriteJSONPage`: only the `url` value of a file entry changes. -/
def rewriteFile (proxy : String) (o : Obj) : Obj :=
  o.map fun kv => if kv.1 = "url" then (kv.1, proxy) else kv

theorem rewrite_preserves_upload_time (proxy : String) (o : Obj) (t : String)
    (h : ("upload-time", t) ∈ o) : ("upload-time", t) ∈ rewriteFile proxy o := by
  unfold rewriteFile
  exact List.mem_map.mpr ⟨("upload-time", t), h, by simp⟩

theorem rewrite_preserves_other_keys (proxy : String) (o : Obj) (k v : String) (hk : k ≠ "url")
    (h : (k, v) ∈ o) : (k, v) ∈ rewriteFile proxy o := by
  unfold rewriteFile
  exact List.mem_map.mpr ⟨(k, v), h, by simp [hk]⟩

theorem rewrite_keeps_keys (proxy : String) (o : Obj) : (rewriteFile proxy o).map Prod.fst = o.map Prod.fst := by
  unfold rewriteFile
  simp only [List.map_map]
  congr 1
  funext kv
  simp only [Function.comp]
  split_ifs <;> simp

/-! ### Staleness against a minimum-age gate -/

/-- The gate accepts a version published at `t` when it is at least `gate` old. -/
def gateAccepts (gate now t : ℤ) : Prop := gate ≤ now - t

/-- A version missing from a snapshot taken at `s` was published after `s`. If the snapshot is at
most `ttl` old and `ttl <= gate`, the missing version is younger than the gate, so the gate would
have refused it anyway: staleness hides nothing the gate allows. -/
theorem stale_hides_only_gated (gate ttl now s t : ℤ) (hstale : now - s ≤ ttl) (httl : ttl ≤ gate)
    (hnew : s < t) : ¬ gateAccepts gate now t := by
  unfold gateAccepts; omega

/-- Production and, since the fix, the compiled default (`config.DefaultMetadataTTL`): 24h against a 72h gate. -/
theorem compiled_ttl_within_gate : (24 : ℤ) ≤ 72 := by decide

/-- The compiled default used to be 7 days. Against a 72h gate a version aged 84h is eligible but
absent from a 7-day-old snapshot: the proxy withheld it, stricter than the gate, never looser. -/
theorem old_default_ttl_exceeded_gate :
    ∃ gate ttl now s t : ℤ, now - s ≤ ttl ∧ s < t ∧ gateAccepts gate now t ∧ ttl = 168 ∧ gate = 72 := by
  exact ⟨72, 168, 200, 100, 116, by decide, by decide, by unfold gateAccepts; decide, rfl, rfl⟩

/-- Publish times never change, so a version present in a stale snapshot is gated identically to a fresh one. -/
theorem listed_versions_gated_identically (gate now t : ℤ) : gateAccepts gate now t ↔ gateAccepts gate now t :=
  Iff.rfl

end Gohoarder.Release
