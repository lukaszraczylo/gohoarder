window.BENCHMARK_DATA = {
  "lastUpdate": 1791431878840,
  "repoUrl": "https://github.com/lukaszraczylo/gohoarder",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cbfb16aebd2e1b34e3ef50faf241ae4123ffab20",
          "message": "chore(deps): bump the go_modules group across 1 directory with 3 updates (#129)\n\nBumps the go_modules group with 3 updates in the / directory: [github.com/moby/go-archive](https://github.com/moby/go-archive), [go.opentelemetry.io/otel](https://github.com/open-telemetry/opentelemetry-go) and [google.golang.org/grpc](https://github.com/grpc/grpc-go).\n\n\nUpdates `github.com/moby/go-archive` from 0.2.0 to 0.3.0\n- [Release notes](https://github.com/moby/go-archive/releases)\n- [Changelog](https://github.com/moby/go-archive/blob/main/changes_test.go)\n- [Commits](https://github.com/moby/go-archive/compare/v0.2.0...v0.3.0)\n\nUpdates `go.opentelemetry.io/otel` from 1.39.0 to 1.41.0\n- [Release notes](https://github.com/open-telemetry/opentelemetry-go/releases)\n- [Changelog](https://github.com/open-telemetry/opentelemetry-go/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/open-telemetry/opentelemetry-go/compare/v1.39.0...v1.41.0)\n\nUpdates `google.golang.org/grpc` from 1.79.3 to 1.83.2\n- [Release notes](https://github.com/grpc/grpc-go/releases)\n- [Commits](https://github.com/grpc/grpc-go/compare/v1.79.3...v1.83.2)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/moby/go-archive\n  dependency-version: 0.3.0\n  dependency-type: indirect\n- dependency-name: go.opentelemetry.io/otel\n  dependency-version: 1.41.0\n  dependency-type: indirect\n- dependency-name: google.golang.org/grpc\n  dependency-version: 1.83.1\n  dependency-type: indirect\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-02T13:14:41+01:00",
          "tree_id": "7712f68dbd6b65447325222af7f91b5fcdbee167",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/cbfb16aebd2e1b34e3ef50faf241ae4123ffab20"
        },
        "date": 1790944388150,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 404.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2842394 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 404.5,
            "unit": "ns/op",
            "extra": "2842394 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2842394 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2842394 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 387,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3109815 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 387,
            "unit": "ns/op",
            "extra": "3109815 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3109815 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3109815 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3178,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3178,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3211,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3211,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 116213,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 116213,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9597,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "123232 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9597,
            "unit": "ns/op",
            "extra": "123232 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "123232 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "123232 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.73,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17315691 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.73,
            "unit": "ns/op",
            "extra": "17315691 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17315691 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17315691 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 336.7,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3606226 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 336.7,
            "unit": "ns/op",
            "extra": "3606226 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3606226 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3606226 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lukasz@raczylo.com",
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo"
          },
          "committer": {
            "email": "lukasz@raczylo.com",
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo"
          },
          "distinct": true,
          "id": "1ebb4cfd95f4baccc36d86b30309cc2fc242f54b",
          "message": "fix(smb): use the cloudsoda go-smb2 fork\n\nhirochachacha/go-smb2 has no fix for GO-2026-5051, an out-of-bounds read in ReadDir that govulncheck reports as called from walkPath. The cloudsoda fork carries the fix. Dialer.DialConn replaces Dial.",
          "timestamp": "2026-10-02T13:24:13+01:00",
          "tree_id": "2fbc478f6e040c5e95ad3d3d73221be7e2b3a7b7",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/1ebb4cfd95f4baccc36d86b30309cc2fc242f54b"
        },
        "date": 1790945358042,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 395.8,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2961777 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 395.8,
            "unit": "ns/op",
            "extra": "2961777 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2961777 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2961777 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 386.9,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3114840 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 386.9,
            "unit": "ns/op",
            "extra": "3114840 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3114840 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3114840 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3125,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3125,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3121,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3121,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 118012,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 118012,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9916,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "103128 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9916,
            "unit": "ns/op",
            "extra": "103128 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "103128 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "103128 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.21,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17252356 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.21,
            "unit": "ns/op",
            "extra": "17252356 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17252356 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17252356 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 331.9,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3627207 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 331.9,
            "unit": "ns/op",
            "extra": "3627207 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3627207 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3627207 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d57a21817b53967c434fb0a86aa7565d6f7024f8",
          "message": "chore(deps): bump go.opentelemetry.io/otel/sdk (#149)\n\nBumps the go_modules group with 1 update in the / directory: [go.opentelemetry.io/otel/sdk](https://github.com/open-telemetry/opentelemetry-go).\n\n\nUpdates `go.opentelemetry.io/otel/sdk` from 1.44.0 to 1.45.0\n- [Release notes](https://github.com/open-telemetry/opentelemetry-go/releases)\n- [Changelog](https://github.com/open-telemetry/opentelemetry-go/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/open-telemetry/opentelemetry-go/compare/v1.44.0...v1.45.0)\n\n---\nupdated-dependencies:\n- dependency-name: go.opentelemetry.io/otel/sdk\n  dependency-version: 1.45.0\n  dependency-type: indirect\n  dependency-group: go_modules\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-02T13:56:19+01:00",
          "tree_id": "db342f6e33e98422cac734f9ff9a343e1d4a45f7",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/d57a21817b53967c434fb0a86aa7565d6f7024f8"
        },
        "date": 1790946747384,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 403.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3013425 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 403.5,
            "unit": "ns/op",
            "extra": "3013425 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3013425 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3013425 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 388.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3096141 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 388.5,
            "unit": "ns/op",
            "extra": "3096141 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3096141 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3096141 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3137,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3137,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3123,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3123,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 119712,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "8368 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 119712,
            "unit": "ns/op",
            "extra": "8368 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "8368 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "8368 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9660,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "119262 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9660,
            "unit": "ns/op",
            "extra": "119262 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "119262 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "119262 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.33,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17470623 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.33,
            "unit": "ns/op",
            "extra": "17470623 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17470623 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17470623 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 332.2,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3568623 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 332.2,
            "unit": "ns/op",
            "extra": "3568623 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3568623 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3568623 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lukasz@raczylo.com",
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8fae680cbef27200feb07c48aa490784e3991b7c",
          "message": "Update go.mod and go.sum (#151)",
          "timestamp": "2026-10-03T04:29:22+01:00",
          "tree_id": "d66b07228e70c696e964a42c753da1ee2155d4ed",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/8fae680cbef27200feb07c48aa490784e3991b7c"
        },
        "date": 1790999402445,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 425.1,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3147424 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 425.1,
            "unit": "ns/op",
            "extra": "3147424 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3147424 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3147424 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 386.3,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3112704 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 386.3,
            "unit": "ns/op",
            "extra": "3112704 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3112704 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3112704 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3137,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3137,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3131,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3131,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 120150,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 120150,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9616,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "121312 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9616,
            "unit": "ns/op",
            "extra": "121312 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "121312 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "121312 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.62,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17309772 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.62,
            "unit": "ns/op",
            "extra": "17309772 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17309772 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17309772 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 330.5,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3748426 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 330.5,
            "unit": "ns/op",
            "extra": "3748426 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3748426 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3748426 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "436633bc683beba96de6033cc69e34a4ce2f74af",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-03T16:12:39Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/436633bc683beba96de6033cc69e34a4ce2f74af"
        },
        "date": 1791045064112,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 419.3,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3014545 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 419.3,
            "unit": "ns/op",
            "extra": "3014545 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3014545 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3014545 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 386.3,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3111710 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 386.3,
            "unit": "ns/op",
            "extra": "3111710 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3111710 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3111710 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3131,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3131,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3122,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3122,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 119776,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 119776,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9915,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "118580 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9915,
            "unit": "ns/op",
            "extra": "118580 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "118580 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "118580 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.73,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17437333 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.73,
            "unit": "ns/op",
            "extra": "17437333 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17437333 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17437333 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 332.8,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3636588 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 332.8,
            "unit": "ns/op",
            "extra": "3636588 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3636588 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3636588 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "cc7d822a0a0df350f2246f7b1d90258ec97378cb",
          "message": "chore(deps): update dependency postcss-selector-parser@<6.1.4 to v7\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-03T16:50:54Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/cc7d822a0a0df350f2246f7b1d90258ec97378cb"
        },
        "date": 1791047449086,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 399.1,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3012982 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 399.1,
            "unit": "ns/op",
            "extra": "3012982 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3012982 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3012982 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 386.9,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3105124 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 386.9,
            "unit": "ns/op",
            "extra": "3105124 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3105124 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3105124 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3126,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3126,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3173,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3173,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 117723,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 117723,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9662,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "119746 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9662,
            "unit": "ns/op",
            "extra": "119746 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "119746 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "119746 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.98,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17435043 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.98,
            "unit": "ns/op",
            "extra": "17435043 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17435043 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17435043 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 333,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3621477 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 333,
            "unit": "ns/op",
            "extra": "3621477 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3621477 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3621477 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "80928c6e218d9adfbd9602a470c9b9d36f943791",
          "message": "chore(deps): update dependency @vueuse/core to v15\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-03T17:19:50Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/80928c6e218d9adfbd9602a470c9b9d36f943791"
        },
        "date": 1791049045157,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 409.6,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2706691 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 409.6,
            "unit": "ns/op",
            "extra": "2706691 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2706691 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2706691 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 385.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3110076 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 385.5,
            "unit": "ns/op",
            "extra": "3110076 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3110076 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3110076 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3189,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3189,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3122,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3122,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 117042,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 117042,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9649,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "121446 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9649,
            "unit": "ns/op",
            "extra": "121446 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "121446 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "121446 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 70.94,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17113726 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 70.94,
            "unit": "ns/op",
            "extra": "17113726 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17113726 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17113726 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 340.3,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3642903 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 340.3,
            "unit": "ns/op",
            "extra": "3642903 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3642903 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3642903 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lukasz@raczylo.com",
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo"
          },
          "committer": {
            "email": "lukasz@raczylo.com",
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo"
          },
          "distinct": true,
          "id": "f72b4817208b5c45ce23808eadfb688fb0937779",
          "message": "chore(deps): migrate fiber from v2 to v3\n\nThe automated update changed only go.mod, so the build failed on the old v2 imports. This commit moves the code to the v3 API.\n\nThe commit replaces BodyParser with Bind().Body, Static with the static middleware, and ListenTLS with ListenConfig. It also updates the tests for TestConfig.\n\nFixes #179",
          "timestamp": "2026-10-04T00:50:37+01:00",
          "tree_id": "9d19fab57afad3950036bd78586b5abe7d7edb31",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/f72b4817208b5c45ce23808eadfb688fb0937779"
        },
        "date": 1791072475152,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 399.7,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2988795 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 399.7,
            "unit": "ns/op",
            "extra": "2988795 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2988795 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2988795 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 385.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3040008 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 385.1,
            "unit": "ns/op",
            "extra": "3040008 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3040008 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3040008 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3138,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3138,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3121,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3121,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 119135,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 119135,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9719,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "118134 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9719,
            "unit": "ns/op",
            "extra": "118134 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "118134 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "118134 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.37,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17309488 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.37,
            "unit": "ns/op",
            "extra": "17309488 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17309488 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17309488 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 341.1,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3647871 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 341.1,
            "unit": "ns/op",
            "extra": "3647871 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3647871 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3647871 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "08552d896838d66aaa3e9c0705bc5b71b04554ef",
          "message": "chore(deps): update dependency vite to v8\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-04T04:39:10Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/08552d896838d66aaa3e9c0705bc5b71b04554ef"
        },
        "date": 1791089904443,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 378.9,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3215650 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 378.9,
            "unit": "ns/op",
            "extra": "3215650 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3215650 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3215650 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 351.8,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3407026 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 351.8,
            "unit": "ns/op",
            "extra": "3407026 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3407026 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3407026 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.289,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.289,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2887,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2887,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 57756,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "20629 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 57756,
            "unit": "ns/op",
            "extra": "20629 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "20629 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "20629 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 5540,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "199743 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 5540,
            "unit": "ns/op",
            "extra": "199743 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "199743 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "199743 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 65.98,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "18237118 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 65.98,
            "unit": "ns/op",
            "extra": "18237118 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "18237118 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "18237118 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 322.6,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3705891 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 322.6,
            "unit": "ns/op",
            "extra": "3705891 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3705891 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3705891 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "37874387e72ed058c639c40a21fc9be1c7595ac4",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-04T10:34:08Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/37874387e72ed058c639c40a21fc9be1c7595ac4"
        },
        "date": 1791111100820,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 412.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3060661 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 412.5,
            "unit": "ns/op",
            "extra": "3060661 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3060661 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3060661 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 385.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3017434 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 385.1,
            "unit": "ns/op",
            "extra": "3017434 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3017434 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3017434 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3123,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3123,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3115,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3115,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 118203,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 118203,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9727,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "119890 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9727,
            "unit": "ns/op",
            "extra": "119890 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "119890 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "119890 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 72.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "15819475 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 72.1,
            "unit": "ns/op",
            "extra": "15819475 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "15819475 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "15819475 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 330.3,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3639728 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 330.3,
            "unit": "ns/op",
            "extra": "3639728 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3639728 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3639728 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo",
            "email": "lukasz@raczylo.com"
          },
          "committer": {
            "name": "Lukasz Raczylo",
            "username": "lukaszraczylo",
            "email": "lukasz@raczylo.com"
          },
          "id": "5a2c25d0e659b146d39917cd637c3bdde059eae9",
          "message": "ci(release): do not fail the release on benchmark noise\n\nBenchmarkFilesystemPut measures disk writes on a shared runner and varied by\na factor of two between runs. Between the two compared commits only go.mod\nand go.sum changed. The benchmark action still comments on an alert and\nwrites the summary, but it no longer fails the workflow.",
          "timestamp": "2026-10-04T11:00:51Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/5a2c25d0e659b146d39917cd637c3bdde059eae9"
        },
        "date": 1791111763432,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 429.6,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2827558 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 429.6,
            "unit": "ns/op",
            "extra": "2827558 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2827558 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2827558 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 387.9,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3090543 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 387.9,
            "unit": "ns/op",
            "extra": "3090543 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3090543 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3090543 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3137,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3137,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3129,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3129,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 121078,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 121078,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9876,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "120204 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9876,
            "unit": "ns/op",
            "extra": "120204 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "120204 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "120204 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.89,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17431470 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.89,
            "unit": "ns/op",
            "extra": "17431470 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17431470 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17431470 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 343.8,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3531524 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 343.8,
            "unit": "ns/op",
            "extra": "3531524 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3531524 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3531524 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "34340895a39ebc04af8f7fdc0600ee8888005722",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-05T03:43:27Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/34340895a39ebc04af8f7fdc0600ee8888005722"
        },
        "date": 1791172932542,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 402.2,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3121742 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 402.2,
            "unit": "ns/op",
            "extra": "3121742 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3121742 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3121742 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 386.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3119017 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 386.5,
            "unit": "ns/op",
            "extra": "3119017 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3119017 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3119017 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3114,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3114,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3128,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3128,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 117815,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 117815,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9603,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "123408 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9603,
            "unit": "ns/op",
            "extra": "123408 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "123408 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "123408 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.29,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17463625 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.29,
            "unit": "ns/op",
            "extra": "17463625 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17463625 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17463625 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 330.9,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3635053 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 330.9,
            "unit": "ns/op",
            "extra": "3635053 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3635053 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3635053 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "2e7a3263a53ae2df2e47655ecf5db0ffc401976d",
          "message": "chore(deps): update module github.com/molecule-man/go-brrr to v1.2.0\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-06T03:25:33Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/2e7a3263a53ae2df2e47655ecf5db0ffc401976d"
        },
        "date": 1791258110242,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 441.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2862735 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 441.5,
            "unit": "ns/op",
            "extra": "2862735 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2862735 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2862735 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 485.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "2475855 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 485.1,
            "unit": "ns/op",
            "extra": "2475855 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "2475855 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "2475855 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3533,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3533,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3531,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3531,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 114961,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 114961,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 11776,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "95655 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 11776,
            "unit": "ns/op",
            "extra": "95655 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "95655 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "95655 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 66.55,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17995705 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 66.55,
            "unit": "ns/op",
            "extra": "17995705 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17995705 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17995705 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 313.9,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3780820 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 313.9,
            "unit": "ns/op",
            "extra": "3780820 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3780820 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3780820 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "c58e4f23ff9c1419afd972336e5b64ac6e7b7bb4",
          "message": "chore(deps): update dependency jsdom to v30.1.2\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-07T03:30:53Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/c58e4f23ff9c1419afd972336e5b64ac6e7b7bb4"
        },
        "date": 1791344874876,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 401.2,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3048723 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 401.2,
            "unit": "ns/op",
            "extra": "3048723 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3048723 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3048723 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 386.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3102745 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 386.5,
            "unit": "ns/op",
            "extra": "3102745 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3102745 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3102745 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3124,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3124,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3162,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3162,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 117568,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 117568,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 35,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9695,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "121549 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9695,
            "unit": "ns/op",
            "extra": "121549 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "121549 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "121549 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.99,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17275732 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.99,
            "unit": "ns/op",
            "extra": "17275732 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17275732 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17275732 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 328.4,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3658196 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 328.4,
            "unit": "ns/op",
            "extra": "3658196 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3658196 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3658196 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "41898282+github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "e1715cdc7a7c411e9fe1ddd05c7d5be0f1957e89",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-08T03:40:38Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/e1715cdc7a7c411e9fe1ddd05c7d5be0f1957e89"
        },
        "date": 1791431878187,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 237,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "5411484 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 237,
            "unit": "ns/op",
            "extra": "5411484 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "5411484 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "5411484 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 269.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "4408419 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 269.1,
            "unit": "ns/op",
            "extra": "4408419 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "4408419 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4408419 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2278,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2278,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2254,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2254,
            "unit": "ns/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 81178,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "15034 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 81178,
            "unit": "ns/op",
            "extra": "15034 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "15034 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "15034 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 6893,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "157600 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 6893,
            "unit": "ns/op",
            "extra": "157600 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "157600 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "157600 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 66.8,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17969398 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 66.8,
            "unit": "ns/op",
            "extra": "17969398 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17969398 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17969398 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 175.5,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "6786436 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 175.5,
            "unit": "ns/op",
            "extra": "6786436 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "6786436 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "6786436 times\n4 procs"
          }
        ]
      }
    ]
  }
}