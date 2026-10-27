window.BENCHMARK_DATA = {
  "lastUpdate": 1793072641330,
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
          "id": "9c2da8fe7a40fc5d4b5d7dcdd777d4994fc33f5e",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-09T03:26:31Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/9c2da8fe7a40fc5d4b5d7dcdd777d4994fc33f5e"
        },
        "date": 1791517465917,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 331.9,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3762033 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 331.9,
            "unit": "ns/op",
            "extra": "3762033 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3762033 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3762033 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 375.3,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3193012 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 375.3,
            "unit": "ns/op",
            "extra": "3193012 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3193012 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3193012 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.274,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.274,
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
            "value": 0.2734,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2734,
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
            "value": 90125,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "13108 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 90125,
            "unit": "ns/op",
            "extra": "13108 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "13108 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13108 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9538,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "130611 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9538,
            "unit": "ns/op",
            "extra": "130611 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "130611 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "130611 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.82,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "22980742 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.82,
            "unit": "ns/op",
            "extra": "22980742 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "22980742 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "22980742 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 250.9,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4853554 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 250.9,
            "unit": "ns/op",
            "extra": "4853554 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4853554 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4853554 times\n4 procs"
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
          "id": "1bb258ef59a359b950c7e234792ea0dbc3ffda9d",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-10T03:39:05Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/1bb258ef59a359b950c7e234792ea0dbc3ffda9d"
        },
        "date": 1791604476984,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 221.6,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "5581509 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 221.6,
            "unit": "ns/op",
            "extra": "5581509 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "5581509 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "5581509 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 271.9,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "4348753 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 271.9,
            "unit": "ns/op",
            "extra": "4348753 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "4348753 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "4348753 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2271,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2271,
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
            "value": 0.2229,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2229,
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
            "value": 81619,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "14527 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 81619,
            "unit": "ns/op",
            "extra": "14527 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "14527 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "14527 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 7182,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "164486 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 7182,
            "unit": "ns/op",
            "extra": "164486 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "164486 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "164486 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 67.54,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "16633038 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 67.54,
            "unit": "ns/op",
            "extra": "16633038 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "16633038 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "16633038 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 173,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "6892680 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 173,
            "unit": "ns/op",
            "extra": "6892680 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "6892680 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "6892680 times\n4 procs"
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
          "id": "616abc8701c053851a3e71c0826da9bdfb3b651f",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-11T03:34:12Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/616abc8701c053851a3e71c0826da9bdfb3b651f"
        },
        "date": 1791690490721,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 347.8,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3524167 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 347.8,
            "unit": "ns/op",
            "extra": "3524167 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3524167 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3524167 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 212.2,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "5358204 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 212.2,
            "unit": "ns/op",
            "extra": "5358204 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "5358204 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "5358204 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.1306,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.1306,
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
            "value": 0.123,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.123,
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
            "value": 43989,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 43989,
            "unit": "ns/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "29910 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 3877,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "272264 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 3877,
            "unit": "ns/op",
            "extra": "272264 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "272264 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "272264 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 49.72,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "24058905 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 49.72,
            "unit": "ns/op",
            "extra": "24058905 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "24058905 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "24058905 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 219.3,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "5433780 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 219.3,
            "unit": "ns/op",
            "extra": "5433780 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "5433780 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "5433780 times\n4 procs"
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
          "id": "1a7f45c6f5bc7a48abfe216da8462c5658e48e2f",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-12T03:49:41Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/1a7f45c6f5bc7a48abfe216da8462c5658e48e2f"
        },
        "date": 1791778004486,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 324.9,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3927226 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 324.9,
            "unit": "ns/op",
            "extra": "3927226 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3927226 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3927226 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 374.8,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3195745 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 374.8,
            "unit": "ns/op",
            "extra": "3195745 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3195745 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3195745 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2735,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2735,
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
            "value": 0.2737,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2737,
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
            "value": 89105,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "13333 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 89105,
            "unit": "ns/op",
            "extra": "13333 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "13333 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13333 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9444,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "122761 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9444,
            "unit": "ns/op",
            "extra": "122761 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "122761 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "122761 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.71,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "23135289 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.71,
            "unit": "ns/op",
            "extra": "23135289 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "23135289 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "23135289 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 250.8,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4837147 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 250.8,
            "unit": "ns/op",
            "extra": "4837147 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4837147 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4837147 times\n4 procs"
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
          "id": "0b6104d01f58dbcc56c3472287694bf53d925281",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-13T03:28:02Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/0b6104d01f58dbcc56c3472287694bf53d925281"
        },
        "date": 1791863068737,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 357.4,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3471038 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 357.4,
            "unit": "ns/op",
            "extra": "3471038 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3471038 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3471038 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 410.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "2926452 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 410.5,
            "unit": "ns/op",
            "extra": "2926452 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "2926452 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "2926452 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.302,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.302,
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
            "value": 0.3045,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3045,
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
            "value": 100192,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 100192,
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
            "value": 10354,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "115917 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 10354,
            "unit": "ns/op",
            "extra": "115917 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "115917 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "115917 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 56.77,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "20379424 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 56.77,
            "unit": "ns/op",
            "extra": "20379424 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "20379424 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "20379424 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 269.6,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4449158 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 269.6,
            "unit": "ns/op",
            "extra": "4449158 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4449158 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4449158 times\n4 procs"
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
          "id": "93d78c141dbd9547022550e90b084a95f7e24d10",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-14T03:22:51Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/93d78c141dbd9547022550e90b084a95f7e24d10"
        },
        "date": 1791949166863,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 407.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2889070 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 407.5,
            "unit": "ns/op",
            "extra": "2889070 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2889070 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2889070 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 391.9,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3009769 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 391.9,
            "unit": "ns/op",
            "extra": "3009769 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3009769 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3009769 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3141,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3141,
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
            "value": 0.3138,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3138,
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
            "value": 118344,
            "unit": "ns/op\t    2516 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 118344,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2516,
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
            "value": 9839,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "113610 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9839,
            "unit": "ns/op",
            "extra": "113610 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "113610 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "113610 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.89,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17330667 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.89,
            "unit": "ns/op",
            "extra": "17330667 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17330667 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17330667 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 345.8,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3422072 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 345.8,
            "unit": "ns/op",
            "extra": "3422072 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3422072 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3422072 times\n4 procs"
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
          "id": "e5026bc422797f115c2522cc0f6495ff124396d4",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-15T03:29:33Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/e5026bc422797f115c2522cc0f6495ff124396d4"
        },
        "date": 1792036101057,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 355.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3680266 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 355.5,
            "unit": "ns/op",
            "extra": "3680266 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3680266 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3680266 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 378.4,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3189316 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 378.4,
            "unit": "ns/op",
            "extra": "3189316 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3189316 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3189316 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.273,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.273,
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
            "value": 0.2732,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2732,
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
            "value": 88485,
            "unit": "ns/op\t    2514 B/op\t      36 allocs/op",
            "extra": "13597 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 88485,
            "unit": "ns/op",
            "extra": "13597 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "13597 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13597 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9332,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "133126 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9332,
            "unit": "ns/op",
            "extra": "133126 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "133126 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "133126 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.68,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "23033845 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.68,
            "unit": "ns/op",
            "extra": "23033845 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "23033845 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "23033845 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 253.2,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4927254 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 253.2,
            "unit": "ns/op",
            "extra": "4927254 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4927254 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4927254 times\n4 procs"
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
          "id": "afb61661abec4dfe119580e09fbfef671a9bea3b",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-16T03:28:43Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/afb61661abec4dfe119580e09fbfef671a9bea3b"
        },
        "date": 1792122443797,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 351.9,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3621982 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 351.9,
            "unit": "ns/op",
            "extra": "3621982 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3621982 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3621982 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 375.4,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3195121 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 375.4,
            "unit": "ns/op",
            "extra": "3195121 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3195121 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3195121 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2749,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2749,
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
            "value": 0.2744,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2744,
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
            "value": 89923,
            "unit": "ns/op\t    2514 B/op\t      36 allocs/op",
            "extra": "13185 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 89923,
            "unit": "ns/op",
            "extra": "13185 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "13185 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13185 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9202,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "131617 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9202,
            "unit": "ns/op",
            "extra": "131617 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "131617 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "131617 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.74,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "23170495 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.74,
            "unit": "ns/op",
            "extra": "23170495 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "23170495 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "23170495 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 248.6,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4838581 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 248.6,
            "unit": "ns/op",
            "extra": "4838581 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4838581 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4838581 times\n4 procs"
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
          "id": "1c70a4f643bbe25d2da40c68d2185e674c3236f0",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-17T03:31:13Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/1c70a4f643bbe25d2da40c68d2185e674c3236f0"
        },
        "date": 1792208890215,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 412.8,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2866323 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 412.8,
            "unit": "ns/op",
            "extra": "2866323 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2866323 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2866323 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 385.4,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3111201 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 385.4,
            "unit": "ns/op",
            "extra": "3111201 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3111201 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3111201 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.313,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.313,
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
            "value": 118358,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 118358,
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
            "value": 9593,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "120748 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9593,
            "unit": "ns/op",
            "extra": "120748 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "120748 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "120748 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 69.26,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17409673 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 69.26,
            "unit": "ns/op",
            "extra": "17409673 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17409673 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17409673 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 336.7,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3648345 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 336.7,
            "unit": "ns/op",
            "extra": "3648345 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3648345 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3648345 times\n4 procs"
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
          "id": "ebedc37ffbf51aa0dabf43c24cce52c357bf0f06",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-18T03:32:06Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/ebedc37ffbf51aa0dabf43c24cce52c357bf0f06"
        },
        "date": 1792295326159,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 402.7,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2991080 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 402.7,
            "unit": "ns/op",
            "extra": "2991080 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2991080 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2991080 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 385,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3112418 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 385,
            "unit": "ns/op",
            "extra": "3112418 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3112418 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3112418 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3121,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3121,
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
            "value": 0.3157,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3157,
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
            "value": 119960,
            "unit": "ns/op\t    2515 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 119960,
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
            "value": 9685,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "121588 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9685,
            "unit": "ns/op",
            "extra": "121588 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "121588 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "121588 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.49,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17494395 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.49,
            "unit": "ns/op",
            "extra": "17494395 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17494395 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17494395 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 330.1,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3696598 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 330.1,
            "unit": "ns/op",
            "extra": "3696598 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3696598 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3696598 times\n4 procs"
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
          "id": "0c6a143c2abd8a13d4b72ee6dbb96888fa499b80",
          "message": "chore(deps): update module github.com/philhofer/fwd to v1.2.1\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-19T03:28:07Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/0c6a143c2abd8a13d4b72ee6dbb96888fa499b80"
        },
        "date": 1792381563936,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 394.5,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "2920762 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 394.5,
            "unit": "ns/op",
            "extra": "2920762 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "2920762 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "2920762 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 385.2,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3106101 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 385.2,
            "unit": "ns/op",
            "extra": "3106101 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3106101 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3106101 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3121,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3121,
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
            "value": 0.3125,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3125,
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
            "value": 117119,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 117119,
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
            "value": 9598,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "123265 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9598,
            "unit": "ns/op",
            "extra": "123265 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "123265 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "123265 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.37,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17516643 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.37,
            "unit": "ns/op",
            "extra": "17516643 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17516643 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17516643 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 325.8,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3700653 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 325.8,
            "unit": "ns/op",
            "extra": "3700653 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3700653 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3700653 times\n4 procs"
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
          "id": "b576bb19b124164b0c16a261e4da638aa085ee79",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-21T03:35:55Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/b576bb19b124164b0c16a261e4da638aa085ee79"
        },
        "date": 1792554748430,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 421.6,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3107919 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 421.6,
            "unit": "ns/op",
            "extra": "3107919 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3107919 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3107919 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 361.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3354326 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 361.5,
            "unit": "ns/op",
            "extra": "3354326 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3354326 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3354326 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2897,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2897,
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
            "value": 0.2903,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2903,
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
            "value": 58837,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "20596 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 58837,
            "unit": "ns/op",
            "extra": "20596 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "20596 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "20596 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 5990,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "199953 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 5990,
            "unit": "ns/op",
            "extra": "199953 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "199953 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "199953 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 65.97,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "18109054 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 65.97,
            "unit": "ns/op",
            "extra": "18109054 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "18109054 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "18109054 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 344.2,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3510106 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 344.2,
            "unit": "ns/op",
            "extra": "3510106 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3510106 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3510106 times\n4 procs"
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
          "id": "9913fdabfe7e9c01447c4ea4974e3f23584f4f0e",
          "message": "chore(deps): update module github.com/gofiber/schema to v1.9.0\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-23T03:26:57Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/9913fdabfe7e9c01447c4ea4974e3f23584f4f0e"
        },
        "date": 1792726968198,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 318.8,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3930148 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 318.8,
            "unit": "ns/op",
            "extra": "3930148 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3930148 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3930148 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 378.3,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3180610 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 378.3,
            "unit": "ns/op",
            "extra": "3180610 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3180610 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3180610 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2809,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2809,
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
            "value": 0.274,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.274,
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
            "value": 87421,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 87421,
            "unit": "ns/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13494 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9021,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "133162 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9021,
            "unit": "ns/op",
            "extra": "133162 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "133162 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "133162 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.91,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "22997641 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.91,
            "unit": "ns/op",
            "extra": "22997641 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "22997641 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "22997641 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 243.5,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4907821 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 243.5,
            "unit": "ns/op",
            "extra": "4907821 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4907821 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4907821 times\n4 procs"
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
          "id": "61d633dfeb9134ba96b02e5010d8e2d009d2983d",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-24T03:29:51Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/61d633dfeb9134ba96b02e5010d8e2d009d2983d"
        },
        "date": 1792813541721,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 394.9,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3089979 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 394.9,
            "unit": "ns/op",
            "extra": "3089979 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3089979 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3089979 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 397.8,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3005624 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 397.8,
            "unit": "ns/op",
            "extra": "3005624 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3005624 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3005624 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.3119,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3119,
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
            "value": 115242,
            "unit": "ns/op\t    2514 B/op\t      35 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 115242,
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
            "value": 9636,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "123295 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9636,
            "unit": "ns/op",
            "extra": "123295 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "123295 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "123295 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.74,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17544962 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.74,
            "unit": "ns/op",
            "extra": "17544962 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17544962 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17544962 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 325.6,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3678330 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 325.6,
            "unit": "ns/op",
            "extra": "3678330 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3678330 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3678330 times\n4 procs"
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
          "id": "61cc52380f297d4be5347b6ab4daffd59eeba24b",
          "message": "chore(deps): update dependencies\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-25T03:36:45Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/61cc52380f297d4be5347b6ab4daffd59eeba24b"
        },
        "date": 1792900389737,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 348,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3603000 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 348,
            "unit": "ns/op",
            "extra": "3603000 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3603000 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3603000 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 376,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3188389 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 376,
            "unit": "ns/op",
            "extra": "3188389 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3188389 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3188389 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2775,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2775,
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
            "value": 0.2744,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2744,
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
            "value": 88784,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "13386 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 88784,
            "unit": "ns/op",
            "extra": "13386 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "13386 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13386 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9244,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "119134 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9244,
            "unit": "ns/op",
            "extra": "119134 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "119134 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "119134 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.68,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "23169122 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.68,
            "unit": "ns/op",
            "extra": "23169122 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "23169122 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "23169122 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 246.3,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4779322 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 246.3,
            "unit": "ns/op",
            "extra": "4779322 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4779322 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4779322 times\n4 procs"
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
          "id": "bb919aea906bd5f60cb272835ef525908a72093f",
          "message": "chore(deps): update module github.com/prometheus/procfs to v0.23.0\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-26T03:36:29Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/bb919aea906bd5f60cb272835ef525908a72093f"
        },
        "date": 1792986846571,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 317,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3541614 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 317,
            "unit": "ns/op",
            "extra": "3541614 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3541614 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3541614 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 376.2,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3187903 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 376.2,
            "unit": "ns/op",
            "extra": "3187903 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3187903 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3187903 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.2735,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2735,
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
            "value": 0.2735,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.2735,
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
            "value": 88667,
            "unit": "ns/op\t    2515 B/op\t      36 allocs/op",
            "extra": "13518 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 88667,
            "unit": "ns/op",
            "extra": "13518 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2515,
            "unit": "B/op",
            "extra": "13518 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "13518 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 9146,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "132826 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 9146,
            "unit": "ns/op",
            "extra": "132826 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "132826 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "132826 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 51.77,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "23068116 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 51.77,
            "unit": "ns/op",
            "extra": "23068116 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "23068116 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "23068116 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 252.1,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "4874178 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 252.1,
            "unit": "ns/op",
            "extra": "4874178 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "4874178 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "4874178 times\n4 procs"
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
          "id": "b283c43a12bd2b128b6490656a3e88ac639a6fb0",
          "message": "chore(deps): update module github.com/molecule-man/go-brrr to v1.3.1\n\nAutomated dependency update. All tests passed.",
          "timestamp": "2026-10-27T03:25:15Z",
          "url": "https://github.com/lukaszraczylo/gohoarder/commit/b283c43a12bd2b128b6490656a3e88ac639a6fb0"
        },
        "date": 1793072640886,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 383.2,
            "unit": "ns/op\t    1664 B/op\t       3 allocs/op",
            "extra": "3138663 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 383.2,
            "unit": "ns/op",
            "extra": "3138663 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 1664,
            "unit": "B/op",
            "extra": "3138663 times\n4 procs"
          },
          {
            "name": "BenchmarkDefault (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 3,
            "unit": "allocs/op",
            "extra": "3138663 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config)",
            "value": 387.1,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "3107994 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - ns/op",
            "value": 387.1,
            "unit": "ns/op",
            "extra": "3107994 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "3107994 times\n4 procs"
          },
          {
            "name": "BenchmarkValidate (github.com/lukaszraczylo/gohoarder/pkg/config) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "3107994 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors)",
            "value": 0.313,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewError (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.313,
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
            "value": 0.3149,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "1000000000 times\n4 procs"
          },
          {
            "name": "BenchmarkNewErrorWithDetails (github.com/lukaszraczylo/gohoarder/pkg/errors) - ns/op",
            "value": 0.3149,
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
            "value": 49537,
            "unit": "ns/op\t    2514 B/op\t      36 allocs/op",
            "extra": "24544 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 49537,
            "unit": "ns/op",
            "extra": "24544 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2514,
            "unit": "B/op",
            "extra": "24544 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemPut (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 36,
            "unit": "allocs/op",
            "extra": "24544 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem)",
            "value": 8674,
            "unit": "ns/op\t    2376 B/op\t       8 allocs/op",
            "extra": "134727 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - ns/op",
            "value": 8674,
            "unit": "ns/op",
            "extra": "134727 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - B/op",
            "value": 2376,
            "unit": "B/op",
            "extra": "134727 times\n4 procs"
          },
          {
            "name": "BenchmarkFilesystemGet (github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem) - allocs/op",
            "value": 8,
            "unit": "allocs/op",
            "extra": "134727 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 68.5,
            "unit": "ns/op\t       0 B/op\t       0 allocs/op",
            "extra": "17352693 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 68.5,
            "unit": "ns/op",
            "extra": "17352693 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 0,
            "unit": "B/op",
            "extra": "17352693 times\n4 procs"
          },
          {
            "name": "BenchmarkNew (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 0,
            "unit": "allocs/op",
            "extra": "17352693 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid)",
            "value": 329.2,
            "unit": "ns/op\t     184 B/op\t       7 allocs/op",
            "extra": "3602157 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - ns/op",
            "value": 329.2,
            "unit": "ns/op",
            "extra": "3602157 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - B/op",
            "value": 184,
            "unit": "B/op",
            "extra": "3602157 times\n4 procs"
          },
          {
            "name": "BenchmarkString (github.com/lukaszraczylo/gohoarder/pkg/uuid) - allocs/op",
            "value": 7,
            "unit": "allocs/op",
            "extra": "3602157 times\n4 procs"
          }
        ]
      }
    ]
  }
}