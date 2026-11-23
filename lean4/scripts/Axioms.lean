import Gohoarder
import Lean

/-! Fails unless every theorem under `Gohoarder` depends only on `propext`, `Classical.choice` and
`Quot.sound`. Run from `lean4/`: `lake env lean scripts/Axioms.lean`. -/

open Lean Elab Command

elab "#audit_axioms" : command => do
  let env ← getEnv
  let allowed : List Name := [``propext, ``Classical.choice, ``Quot.sound]
  let mut audited : Nat := 0
  let mut bad : Array String := #[]
  for (n, ci) in env.constants.map₁.toList do
    if `Gohoarder |>.isPrefixOf n then
      if let .thmInfo _ := ci then
        audited := audited + 1
        let axs ← liftCoreM (collectAxioms n)
        for a in axs do
          if !allowed.contains a then
            bad := bad.push s!"{n} uses {a}"
  if bad.isEmpty then
    logInfo m!"{audited} theorems audited, axioms within {allowed}"
  else
    throwError "unexpected axioms:\n{"\n".intercalate bad.toList}"

#audit_axioms
