window.BENCHMARK_DATA = {
  "lastUpdate": 1790945359007,
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
      }
    ]
  }
}