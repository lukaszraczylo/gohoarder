import Mathlib

/-!
# Stats and time series

Models `pkg/metadata/gormstore/aggregation_worker.go` (`AggregateHourly`, `AggregateDaily`) and
`pkg/metadata/gormstore/gormstore_v2.go` `GetTimeSeriesStats`. Time is in whole minutes since the
epoch; an hour is 60 minutes and a day 24 hours. Omits: unique IPs, packages, registries.
-/

namespace Gohoarder.Stats

/-! ### Hourly pass: each event is counted once -/

/-- `AggregateHourly`: cutoff hour = floor((now - 5min) / 60); events in earlier hours move to
`hr` and are deleted, in one transaction. -/
def cutoffHour (nowMin : ℤ) : ℤ := (nowMin - 5) / 60

def moveEvents (c : ℤ) (ev hr : ℤ → ℕ) : (ℤ → ℕ) × (ℤ → ℕ) :=
  (fun h => if h < c then 0 else ev h, fun h => hr h + if h < c then ev h else 0)

/-- Per hour, events plus hourly rows are unchanged by a pass: nothing is counted twice or dropped. -/
theorem hourly_pass_conserves (c : ℤ) (ev hr : ℤ → ℕ) (h : ℤ) :
    (moveEvents c ev hr).1 h + (moveEvents c ev hr).2 h = ev h + hr h := by
  simp only [moveEvents]
  split_ifs <;> omega

theorem hourly_pass_conserves_sum (c : ℤ) (ev hr : ℤ → ℕ) (S : Finset ℤ) :
    ∑ h ∈ S, ((moveEvents c ev hr).1 h + (moveEvents c ev hr).2 h) = ∑ h ∈ S, (ev h + hr h) :=
  Finset.sum_congr rfl fun h _ => hourly_pass_conserves c ev hr h

/-- Within five minutes after the hour the cutoff is still the previous hour, so the last hour of a
day is not aggregated by a pass at `hh:00`-`hh:04`. -/
theorem early_tick_leaves_last_hour (hourIdx m : ℤ) (hm0 : 0 ≤ m) (hm : m < 5) :
    cutoffHour (60 * hourIdx + m) = hourIdx - 1 := by
  unfold cutoffHour; omega

theorem late_tick_covers_last_hour (hourIdx m : ℤ) (hm0 : 5 ≤ m) (hm : m < 60) :
    cutoffHour (60 * hourIdx + m) = hourIdx := by
  unfold cutoffHour; omega

/-! ### Daily pass: which days are rolled up -/

def retentionDays : ℕ := 7
/-- Days recomputed by each pass (`rollupDays`). -/
def rollupDays : ℕ := 6

/-- A pass on day `t` rolls up day `d` (before: only yesterday). -/
def oldRolls (t d : ℕ) : Prop := d + 1 = t
def newRolls (t d : ℕ) : Prop := d + 1 ≤ t ∧ t ≤ d + rollupDays

theorem rollup_window_below_retention : rollupDays < retentionDays := by decide

/-- The pass on day `t` deletes hourly rows older than 7 days: hours of day `d` survive it
whenever `t < d + 7`. The new window ends at `d + 6`, inside that bound. -/
theorem new_window_inside_retention (t d : ℕ) (h : newRolls t d) : t < d + retentionDays := by
  unfold newRolls at h; unfold retentionDays rollupDays at *; omega

/-- A day is rolled up if some pass day (hour-0 tick) falls in its window. -/
def covered (rolls : ℕ → ℕ → Prop) (passes : Set ℕ) (d : ℕ) : Prop := ∃ t ∈ passes, rolls t d

/-- Before: skipping the one pass on day d+1 (restart at midnight) loses day d for good. -/
theorem old_loses_day_on_one_skip (d : ℕ) :
    ¬ covered oldRolls {t | t ≠ d + 1} d := by
  rintro ⟨t, ht, h⟩
  unfold oldRolls at h
  exact ht h.symm

/-- After: any single surviving pass in the next six days repairs it. -/
theorem new_repairs_after_skip (d : ℕ) : covered newRolls {t | t ≠ d + 1} d :=
  ⟨d + 2, by simp, by unfold newRolls rollupDays; omega⟩

/-! ### Chart: rollup against hourly rows and events -/

/-- Before: `counts[day] = rollup`. After: the larger of rollup and hourly+events. -/
def chartOld (rollup live : ℕ) : ℕ := rollup
def chartNew (rollup live : ℕ) : ℕ := max rollup live

/-- Rollup and live (hourly rows + events) each count a subset of the day's downloads, so the
larger is the better lower bound and never exceeds the truth. -/
theorem chartNew_sound (truth rollup live : ℕ) (hr : rollup ≤ truth) (hl : live ≤ truth) :
    chartNew rollup live ≤ truth := max_le hr hl

theorem chartNew_never_drops (rollup live : ℕ) : chartOld rollup live ≤ chartNew rollup live :=
  le_max_left _ _

/-- A download aggregated after the rollup ran: the old chart shows 1 of 2. -/
theorem chartOld_drops_late_download : chartOld 1 2 < chartNew 1 2 := by decide

/-! ### SQLite upsert (`aggregation_worker.go`, `sqlite_stats.go`) -/

/-- A bucket is a list of stored rows; the chart sums them. Before the fix SQLite had no unique index,
so `INSERT OR REPLACE` appended a row per pass. -/
def chartTotal (rows : List ℕ) : ℕ := rows.sum

/-- Three passes over a bucket whose registry total is 3: three copies. -/
theorem old_sqlite_duplicates_rows : chartTotal [3, 3, 3] ≠ 3 := by decide

/-- `ON CONFLICT ... DO UPDATE` over the unique index keeps one row per bucket: a derived row is set,
a package row adds the new events, as on PostgreSQL. -/
def upsertDerived (_old new : ℕ) : List ℕ := [new]
def upsertAdditive (old new : ℕ) : List ℕ := [old + new]

theorem fixed_sqlite_registry_row_idempotent (old new : ℕ) :
    chartTotal (upsertDerived old new) = new := by simp [chartTotal, upsertDerived]

theorem fixed_sqlite_package_row_keeps_late_events (old new : ℕ) :
    chartTotal (upsertAdditive old new) = old + new := by simp [chartTotal, upsertAdditive]

end Gohoarder.Stats
