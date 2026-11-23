# Lean audit findings

Audit of GoHoarder at c98720c (v0.1.303) with Lean 4 + Mathlib v4.36.0. Models live in
`lean4/Gohoarder/*.lean`; each cites the Go files it models. Statements are "proved about the model".
A Lean counterexample is never the evidence alone: every fixed row has a Go test that failed first.

Build: `cd lean4 && lake exe cache get && lake build && lake env lean scripts/Axioms.lean`.
Currency: `sh lean4/scripts/check_currency.sh origin/main`.

## Fixed

| id | area | claim | class | severity | evidence (Lean / Go test) | fix commit |
|----|------|-------|-------|----------|---------------------------|------------|
| GH-01 | PyPI fetch | the file fetched from `original_url` is the file the cache key names | security, CWE-345 | high | `Access.old_guard_allows_key_poisoning`, `fixed_guard_binds_key` / `TestHandlePackageFile_OriginalURLFilenameBound` | 5c9f7e6 |
| GH-02 | scan decision | a bypassed CVE never blocks, under any `block_on_severity` | correctness (over-block) | low | `Security.old_low_ignores_bypass`, `fully_bypassed_never_blocks` / `TestCheckVulnerabilities_BypassedCVENeverBlocks` | 4713524 |
| GH-03 | PyPI scan | scanners are asked about the release version, not the file name | security, CWE-693 | high when a block policy is set | `Security.scan_asks_release_version`, `file_name_is_not_release_version` / `TestScanAsksScannersForReleaseVersion` | 3143de3 |
| GH-04 | scan gate | an npm or PyPI package named `*.info` or `*.mod` is scanned | security, CWE-693 | medium | `Cache.npm_named_like_go_metadata_is_scanned`, `old_exempted_npm_package` / `TestCacheHitScansPackagesNamedLikeGoMetadata`, `TestIsMetadataEntry` | f0b37ea |
| GH-05 | storage quota | `used` equals bytes on disk after an overwrite | correctness | low | `Cache.put_keeps_usage_exact`, `old_put_inflates_usage` / `TestPutOverwriteKeepsUsageExact`, `TestPutOverwriteWithinQuota` | 1f31256 |
| GH-06 | LRU eviction | eviction terminates; an overlapping store waits instead of failing | correctness | medium | `Cache.old_evict_is_stuck`, `fixed_evict_measure_falls` / `TestEvictTerminatesWhenDeletesFail`, `TestEvictWaitsForRunningEviction` | 440279a |
| GH-07 | get vs purge | a purge between probe and open does not fail the request | correctness | low | `Cache.getOnce_errors_on_purge`, `getRetry_survives_one_purge` / `TestGetRecoversFromPurgeBetweenProbeAndOpen` | 990a1d3 |
| GH-08 | stats rollup | every completed day still held hourly is rolled up | correctness (data loss) | medium | `Stats.old_loses_day_on_one_skip`, `new_repairs_after_skip`, `early_tick_leaves_last_hour` / `TestDailyRollupKeepsLastHourOfDay`, `TestDailyRollupCoversMissedDay`, `TestPostgresDailyRollupCoversMissedDay` | ad4e848 |
| GH-09 | stats chart | a rollup never hides downloads counted after it ran | correctness | low | `Stats.chartOld_drops_late_download`, `chartNew_sound` / `TestTimeSeriesKeepsLateDownloadsAheadOfRollup` | 7192e4f |
| GH-15 | release age | a cached packument or index stays fresh no longer than the client's 72h release-age gate | correctness (config default) | low | `Release.compiled_ttl_within_gate`, `old_default_ttl_exceeded_gate` / `TestMetadataEntryDefaultTTLIsBelowReleaseAgeGate`, `TestMetadataEntryExplicitTTLWins`, `TestDefaultMetadataTTL`, `TestShippedExamplesKeepMetadataTTLWithinGate` | 549d56e |
| GH-17 | CORS, auth off | a page at a foreign origin cannot read `/api` or change state through a visitor's browser | security, CWE-352 / CWE-942 | medium with `auth.enabled: false` | `Access.old_cors_admits_any_page`, `fixed_refuses_foreign_origin` / `TestAPIDeleteFromDisallowedOriginForbidden`, `TestAPIDeleteFromAllowedOriginWorks`, `TestAPIPreflightAnswersOnlyAllowedOrigins`, `TestAPIGetStaysPublicWithoutWildcardCORS`, `TestAPISameOriginRuleWhenNoOriginsConfigured` | f204938 |
| GH-18 | api keys | `ValidateAPIKey` costs one bcrypt compare, whatever the number of stored keys | hardening, CWE-400 | low | `Access.old_cost_grows_with_keys`, `new_cost_independent_of_keys` / `TestValidateAPIKeyCostIndependentOfKeyCount`, `TestLegacyComparesAreConcurrencyBounded` | ae5167f |
| GH-19 | SSRF | every redirect hop passes the upstream allowlist, the scheme rule and a non-private address check | security, CWE-918 | medium | `Access.redirect_escapes_allowlist`, `fixed_redirect_stays_allowlisted` / `TestRedirectToDisallowedHostRefused`, `TestRedirectToLoopbackRefused`, `TestRedirectToPrivateLiteralRefused`, `TestRedirectAllowedToAllowedWorks`, `TestRedirectHopsCapped`, `TestSidecarRedirectOffAllowlistRefused` | 787c757 |
| GH-20 | stats, sqlite | SQLite upserts hourly and daily rows as PostgreSQL does, one row per bucket | correctness | low (SQLite only) | `Stats.old_sqlite_duplicates_rows`, `fixed_sqlite_package_row_keeps_late_events` / `TestSQLiteHourlyTotalsMatchPostgresSemantics`, `TestPostgresHourlyTotalsMatchSQLite`, `TestSQLiteDailyRollupIsIdempotent`, `TestSQLiteStatsDedupeMigration` | f46e079 |
| GH-21 | scan retry | a scan retry on S3 or SMB storage reads the stored blob instead of a removed temp file | correctness | low (file-based scanners on remote storage) | `Security.old_remote_retry_unreadable`, `fixed_retry_always_readable` / `TestScanRetryOnRemoteStorageReadsBlobAgain` | 31db940 |
| GH-22 | dashboard API | an OIDC-logged-in browser can call `/api` with a long URL; the proxy hop neither forwards session cookies nor exceeds the read buffer | availability | medium (every `/api` call returned 431 for OIDC users) | not modelled (header size, no decision logic) / `TestLargeRequestHeadersAreAccepted`, `TestReadBufferSizeIsConfigurable`, `scripts/check_frontend_cookie_strip.sh` | 536f35a |
| GH-23 | PyPI sidecar | pip's PEP 658 request (`<link>.metadata`, suffix on `original_url`) is served as its wheel's sidecar; another file's sidecar is still refused | correctness (pip install failed with 400) | medium (every pip install through the proxy) | `Access.pip_form_keeps_key_binding`, `pip_sidecar_of_other_file_rejected`, `pip_sidecar_of_same_file_accepted` / `TestPipSidecarFormIsStreamed`, `TestHandlePackageFile_OriginalURLFilenameBound` | 501bf1a |
| GH-24 | rescan | with `security.rescan_interval` set, artifacts whose scan never completed are scanned and old results refreshed | correctness (scans lost to a restart stayed unscanned; new CVEs never picked up) | medium | not modelled (worker wiring) / `TestWorkersStartTheRescanWorker` | 378b873 |
| GH-25 | scanners | an error result from one scanner is left out of the merge, so the row reads error only when every scanner failed; grype, npm-audit, govulncheck and pip-audit give correct results with the scanner image tool versions | correctness (false error, false clean) | high (grype, npm-audit and pip-audit failed on every package; govulncheck and a bare-archive grype scan read vulnerable packages clean) | `Security.old_error_poisons_clean`, `error_and_clean_reads_clean`, `all_error_reads_error`, `merged_not_error_when_one_ran` / `TestScanPackage_ErrorResultPlusCleanReadsClean`, `TestScanPackage_AllErrorResultsReadError`, `TestScanPackage_InfrastructureErrorResultsCountAsInfrastructure`, `TestScanMapsRealOutput`, `TestParseKeepsBothViaShapes`, `TestScanReadsPrettyPrintedFindings`, `TestScanAuditsTheReleaseFromARequirement` | 3731ca0 |
| GH-26 | rescan | the rescan worker skips the entries the serve path skips, so Go `.mod` and `.info` rows are no longer scanned | cost (1316 of about 2780 rescans on production were these rows, about 3.3 s each) | low | `Cache.old_rescan_scanned_go_metadata`, `rescan_skips_what_serve_skips` / `TestRescanSkipsMetadataEntries` | d6044cd |

### Exploit paths and reach

- **GH-01.** A client requests `/pypi/<victim>/<victim-file>?original_url=https://files.pythonhosted.org/.../<attacker-file>`.
  The host is on the allowlist, the key is `pypi/<victim>/<victim-file>`, and an uncached key stores the attacker's
  file. Every later client gets it; OSV judges the victim's name and version. The attacker publishes the file on PyPI
  and needs no credentials. Reach: any network client of `/pypi`, unauthenticated when `auth.enabled` is false (production).
- **GH-03.** Live check against `api.osv.dev` for requests 2.19.0: the release version returns 10 advisories; the file name
  returns 12, missing PYSEC-2023-74 and GHSA-j8r2-6x86-q33q. Production has `block_on_severity: none`, so it shows wrong
  scan results rather than serving blocked packages; any deployment with a block policy served such packages.
- **GH-17.** A page at any origin issued `DELETE /api/packages/<registry>/<name>/<version>` from a visitor's browser, and
  `Access-Control-Allow-Origin: *` let it read every `/api` response. Reach: any visitor to a hostile page when
  `auth.enabled` is false (production); impact is cache eviction. Fixed by `apiOriginGuard` against `server.allowed_origins`;
  with none set, only same-origin passes.
- **GH-19.** An allowed host that answered 302 reached any target (`169.254.169.254`, `127.0.0.1`, `10.x`), by name or by
  DNS rebinding. No allowed host redirects today; the fix removes the dependency on that. Hops are capped at 10, limited to
  http(s), vetted against the allowlist, and a hop to another host dials through a guard that refuses private, loopback,
  link-local and carrier-grade addresses after resolution. A redirect inside one host is left alone: a private index is
  operator-trusted.
- **GH-04.** The publisher of an npm or PyPI package named `x.info` skipped the scan and the block policy. Reach: any package
  publisher; needs a block policy to matter.

### Notes on the fixed rows

- **GH-15.** `cache.ttl_overrides` now has a consumer: `cache.Config.TTLOverrides` sets the metadata freshness per registry
  (`npm`, `pypi`, `go`; `pip` is an alias of `pypi`), and a registry without an override keeps `default_ttl`. Artifacts keep no
  age expiry. Defaults hold no override, so lowering `default_ttl` still applies everywhere. Config load rejects an unknown
  registry key or a non-positive value. Tests: `TestMetadataTTLOverridesApplyPerRegistry`, `TestMetadataTTLOverridesSkipArtifacts`,
  `TestNPMMetadataTTLOverrideReachesCache`, `TestTTLOverridesValidation`.
- **GH-18.** New keys read `ghk_<id>.<secret>`; the hash covers the secret and one lookup selects the stored key. A miss
  compares a dummy hash. Keys minted before are accepted through a legacy path capped at 4 concurrent bcrypt compares. They
  cannot be migrated: the raw key holds no id and the stored hash covers the whole raw key. Re-issue them to leave the
  legacy path. Production holds none.
- **GH-20.** SQLite startup merges old duplicate rows (package rows add up, derived rows keep one) and creates the unique indexes.
- **GH-21.** `RescanWorker` reads each blob through the cache `ScanFile` source, so periodic rescans cover S3 and SMB as well as
  local storage. A remote blob is copied to a temp file for the scan and removed after it. Test: `TestRescanWorkerScansRemoteStorage`.
- **GH-22.** Frontend nginx dropped the `Cookie` header on `/api/` and `/ws` (the backend reads none; keys travel in `Authorization` / `X-API-Key`).
  The server read buffer is `server.read_buffer_size`, default 16384 (Fiber's default is 8192): a long Referer or `Authorization` no longer gets 431.
- **GH-25.** `scan` treats an error-status result like a returned error: it is left out of the merge and counted as an
  infrastructure failure (`infrastructure_error` in its details, set on a deadline or an unreachable network) or another failure.
  Before, one such result made the merged row an error and `evaluateScan` blocked the package even with `fail_closed: false`.
  Defects found by running the published scanner image (grype 0.121.2, npm 11.12.1, govulncheck 1.9.0, pip-audit 2.10.1,
  go 1.26), each with a fixture of real output under the scanner's `testdata/`:
  grype: `source.target` is a string for file and purl sources, and a bare archive has nothing to catalog, so minimist 0.0.8 read clean;
  the scanner now passes a purl. npm audit: `via` is an array and `metadata.dependencies` an object in npm 11; the lockfile
  step resolved devDependencies (dayjs: 1567 packages, 142 findings, 28s) and `npm audit` cannot report the root package itself;
  the tarball is now installed into a wrapper project and audited with `--omit=dev` (under 1s). govulncheck: the JSON stream is
  indented, so the line parser read nothing, and govulncheck never reports the main module of the tree it scans (x/text 0.3.5
  read clean); the module is now a dependency of a wrapper module and scanned at module level. pip-audit: its positional
  argument is a project directory and `--pyproject` does not exist, so every scan failed; the release is audited from a pinned
  requirement, an advisory is listed once, and `skip_reason` is an error. trivy is not covered: it reads a bare npm archive
  as clean the same way grype did.
- **GH-17 cleanup.** The per-handler `Access-Control-*` lines in `pkg/app/handlers*.go` are removed; `apiOriginGuard` is the only CORS
  source. `TestHandlersSetNoCORSHeaders` and `TestAPIResponsesNeverCarryWildcardOrigin` guard it.
- **GH-26.** `rescanPackages` kept its own list of metadata versions and never called `IsMetadataEntry`, so Go `.mod` and `.info`
  rows were scanned every cycle. Related options, whose defaults keep the old behaviour: `rescan_active_window` skips packages idle longer than the
  window, `rescan_concurrency` runs scans in parallel, and `rescan_on_access` rescans a stale cache hit before serving it.
  Model of the last: `Security.finished_rescan_verdict_younger_than_interval`, `old_verdict_only_on_timeout`,
  `stale_clean_fresh_vulnerable_blocked`, `timeout_keeps_previous`, `timeout_without_previous_is_miss_rule`, `off_is_old_hit_path`.

## Not fixed

| id | area | claim | verdict | why |
|----|------|-------|---------|-----|
| GH-10 | key path | `keyToPath` rewrites `..` instead of rejecting; distinct keys share a path | hardening, unreachable | `Keys.keyToPath_not_injective`. A probe through the full app showed the HTTP layer resolves literal `..` and answers 404 to encoded slashes (`/npm/lodash/-/lodash-1.0.0/../../x.tgz` reached upstream as `/lodash/-/lodash-x.tgz`). No key with `..` reaches storage. |
| GH-11 | cache hit | the stored SHA-256 is not re-verified on read | by-design | `Put` verifies the stream it just hashed; no doc promises read-side integrity. A check reads up to 2 GB per hit. Disk corruption is outside the proxy's threat model. |
| GH-12 | idle purge | check and delete are two steps, so a request inside the window loses its blob | by-design | `Cache.purge_window_deletes_fresh_entry`. The consequence is a refetch; GH-07 covers the in-flight request. |
| GH-13 | scan policy | with `fail_closed: false` a package whose scan keeps failing on infrastructure is served unscanned | by-design, accepted | See "Decision" below. |
| GH-14 | scan merge | one scanner failing while another returns clean saves a clean result and schedules no retry | by-design | `Security.error_and_clean_reads_clean` (a returned error and, since GH-25, an error-status result). `scan` handles only the all-failed case; redundancy across scanners is the intent. |
| GH-16 | admin API | `requireAdmin` accepts the `bypasses:manage` permission and also guards key minting | tested-clean | Only the admin role holds that permission: `Access.admin_gate_implies_key_manager`. |

### Decision: `fail_closed: false` with recurring infrastructure errors

Served: a package with no scan row while a scan is in flight, and a package whose every scanner failed on infrastructure
(`Security.unscanned_served_iff`, `infra_error_served_forever`). Retries: at most 6 at 5 minute spacing, 7 scans, 30
minutes (`retry_terminates`, `retry_window_minutes`); after that the error row stays and the package stays served until
the rescan worker runs (needs `rescan_interval`). Quoted intent: `pkg/cache/cache.go` "A wait that times out serves the
package unless FailClosed is set"; `scanner.go` "Scan failed on infrastructure, serving package; scan will be retried";
production config "A scan that fails on infrastructure is retried and the package is served (fail_closed false)".
Verdict: acceptable for production, whose only scanner is OSV, a remote service that cannot be made to time out by package
content. Residual risk: with file-based scanners (trivy, grype, pip-audit) a crafted package that makes the scanner time out
is served unscanned, because a deadline counts as infrastructure. Run those with `fail_closed: true`. No code change.

## Negative matrices (do not re-run)

| surface | runs | a leak would look like | verdict |
|---------|------|------------------------|---------|
| frontend nginx blocklist (`Dockerfile.frontend` template on nginx:alpine, stub backend) | 30 raw paths: `//npm`, `/./npm`, `%6Epm`, `/api/../npm`, `/api/..%2fnpm`, `/health/..%2fnpm`, `/ws/..%2fnpm`, `/api/..\npm`, `/api/..;/npm`, `/api/%5c..%5cnpm`, `/api/..%252fnpm`, `/npm?x=1`, `/metrics/` and more | 200 from the backend for `/npm`, `/pypi`, `/go` or `/metrics` | all 404 or SPA. `/NPM/x` returns the SPA page, not the proxy. |
| backend re-interpretation of the six paths nginx forwarded raw | `/api/..\npm/x`, `/api/..;/npm/x`, `/api/%5c..%5cnpm/x`, `/api/%2e%2e%5cnpm/x`, `/api/..%252fnpm/x`, `/api/;/../npm/x` against the full app | 200 from the npm handler | all 404 |
| WebSocket origin check | `Access.default_port_equivalent`, `scheme_mismatch_rejected`, `port_mismatch_rejected`, `glob_rejects_label_prefix`, `glob_rejects_suffix_trick` | an origin outside the allowlist accepted | clean. Same-origin mode compares host only; documented: "the Origin host must match the Host header". |
| history totals under eviction | existing `TestPostgresHistoryTablesHaveNoPackageForeignKey`, `checkDeleteKeepsDownloadHistory` | totals fall after a package delete | clean: history tables carry no foreign key to packages. |
