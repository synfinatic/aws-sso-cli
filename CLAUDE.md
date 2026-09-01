# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development workflow

**Always use TDD for all changes.** This means:

1. Write a failing test that captures the expected behavior before writing any implementation code.
2. Run `make test` to confirm the test fails for the right reason.
3. Write the minimum implementation to make the test pass.
4. Run `make test` again to confirm it passes.
5. Refactor if needed, keeping tests green throughout.

No implementation change is complete without a corresponding test. If a function is hard to test directly,
restructure it so it can be tested — don't skip the test.

**Never create a git commit unless explicitly asked.** Do not commit as a side effect of completing a
task or fix.

Whenever modifying a markdown file, always wrap lines at 100 characters.

Whenever modifying a markdown file, add an empty line after a paragraph
before starting an ordered or unordered list.

Whenever adding new CLI options or commands, be sure to update the documentation in docs to
cover that change.

Whenever modifying the config file data structure definition, be sure to update
the docs to cover that change.

Whenever adding a new feature, fixing a bug or changing behavior add a brief (1-2 line) entry to
the CHANGELOG.md under the Unreleased section under the appropriate `New Features`, `Bugs` or
`Changes` sub-section.

Never run `go build ...` directly to build the aws-sso binary.  Use `make`
instead which places it in the `dist` directory.

## About

AWS SSO CLI is a Go CLI (`aws-sso`) that replaces `aws configure sso` for organizations using
AWS IAM Identity Center (formerly AWS SSO). It manages IAM role credentials, `~/.aws/config`,
and can share credentials across processes via an ECS Task IAM Role emulation server. All SSO
tokens and STS credentials are encrypted at rest via a pluggable secure storage backend
(OS keychain via `99designs/keyring`, 1Password, or an insecure JSON file).

## Build & Test Commands

```bash
make                    # Build ./dist/aws-sso for the current platform
make run PROGRAM_ARGS="list"  # go run ./cmd/aws-sso with args
make unittest           # go test ./... (unit tests only)
make e2e                # go test -tags e2etests ./cmd/aws-sso/...  (mock-AWS integration tests)
make test               # vet + unittest + lint + test-homebrew + test-tidy + test-fmt
make precheck           # what CI runs on a PR: test + test-fmt + test-tidy
make lint               # golangci-lint run (version pinned; `make lint-install` to install it)
make fmt                # gofmt -s -w
make vet                # go vet ./...
make coverage           # e2e-tagged tests with coverage.out
```

Run a single test: `go test -ldflags='$(cat Makefile | grep LDFLAGS)' ./internal/sso/... -run TestName`
in practice `go test ./internal/sso/... -run TestName -v` is sufficient (LDFLAGS only matters for
version string embedding, not test logic). For e2e tests:
`go test -tags e2etests ./cmd/aws-sso/... -run TestName -v`.

The Go toolchain version is pinned via `GOTOOLCHAIN` derived from `go.mod`'s `go` directive
(see the comment block in `Makefile`) — don't fight this if `go build` behaves differently than
a bare local Go install would suggest.

### Two test suites — don't confuse them

- **Unit tests** (`make unittest`, no build tag): fast, package-local, no network/mocked-HTTP.
- **E2E tests** (`make e2e`, build tag `e2etests`): live in `cmd/aws-sso/*_e2e_test.go` and drive
  the CLI's `RunContext`/command `Run()` methods against a mock AWS SSO/OIDC/STS HTTP server
  (`internal/awsmock`, itself gated by `//go:build e2etests`). This is the integration test layer
  — there is no separate `make integration` target.

## Architecture

### Command dispatch (cmd/aws-sso)

`cmd/aws-sso` is a single Go package (not `main` split across subpackages) using
[`alecthomas/kong`](https://github.com/alecthomas/kong) for CLI parsing. Each subcommand is a
`*_cmd.go` file defining a `FooCmd` struct with a `Run(ctx *RunContext) error` method; `cmd/aws-sso/main.go`
declares the top-level `CLI` struct that wires them together via kong tags.

`RunContext` (`main.go`) is the value threaded through every command: parsed CLI args, loaded
`*sso.Settings` (merged config file + cache), the `storage.SecureStorage` backend, an auth
requirement level, and a `context.Context` for cancellation.

Each command declares its auth requirement via the `Auth` field pattern in `main()`:

- `AUTH_NO_CONFIG` — runs before config is loaded (e.g. `setup`, `version`)
- `AUTH_SKIP` — loads config/settings but doesn't require a prior SSO login
- `AUTH_REQUIRED` — requires a valid SSO login; triggers `AutoLogin` if configured, else fatals

`main()` handles SIGINT/SIGTERM via `watchSignals()`, which force-exits with `osExit(1)` from a
dedicated goroutine even if the main goroutine is blocked in an uninterruptible keyring/D-Bus
call — this exists so OS-level file locks (`storage.lock`) get released on Ctrl-C (see #1379).
Don't route this through the cancellable context's own `Done()` — that would also fire on a
normal clean exit and break `aws-sso process` as an AWS `credential_process` (needs exit 0).

### Settings & config layering (internal/sso, internal/sso/config, internal/sso/cache)

`sso.Settings` (`internal/sso/settings.go`) is the merged view of the user's YAML config file
(`internal/sso/config`) and the on-disk insecure cache file (`internal/sso/cache`, JSON — role
metadata, tag indexes, history; distinct from the *secure* store). `sso.LoadSettings()` merges
config file + cache + built-in defaults (`DEFAULT_CONFIG` in `main.go`) + CLI-flag overrides
(`sso.OverrideSettings`). Cross-package coupling is interface-based: `sso.Settings` satisfies
`ssocache.SettingsReader` (see the compile-time assertion in `internal/sso/interfaces.go`) so the
cache package never imports the parent `sso` package back.

### Secure credential storage (internal/storage)

`storage.SecureStorage` (`internal/storage/secure_store.go`) is the interface for anything that
persists SSO tokens / STS role credentials / the ECS bearer token / ECS TLS keypair. Three
implementations, selected by `Settings.SecureStore` and constructed in `loadSecureStore()` in
`main.go`:

- keyring-backed (`internal/storage/keyring.go`) — the default; wraps `99designs/keyring` (macOS
  Keychain, Windows Credential Manager, Secret Service, pass, etc.)
- `internal/storage/onepassword.go` — 1Password CLI/Connect integration (has a `_nocgo` build
  variant for platforms without the 1Password SDK's CGO dependency)
- `internal/storage/json_store.go` — plaintext JSON file, explicitly insecure, logged as a warning
  when selected

`Save*`/`Delete*` methods take a `context.Context` (used for file-lock acquisition timeout/
cancellation); `Get*` methods read from an in-memory cache and don't need one — keep that split
when adding methods to the interface.

### AWS SSO/OIDC auth flow (internal/sso/auth, internal/sso/oidc)

`internal/sso/auth` (`ssoauth.AWSSSO`) drives the actual SSO device-code/PKCE OAuth flow against
AWS SSO OIDC and the SSO API, using `internal/sso/oidc` for the wire protocol. `main.go` keeps a
package-level `AwsSSO *ssoauth.AWSSSO` set up once auth is established.

### Role/account/tag model (internal/sso/roles, internal/tags, internal/awsparse)

Roles and accounts get an auto-discovered and user-defined tag system (`internal/tags`) used for
interactive fuzzy search/autocomplete (`internal/predictor`, `c-bata/go-prompt` driven UI in
`internal/ui`). `internal/awsparse` centralizes ARN/account-ID parsing and validation — e.g. the
`AccountID` custom kong type in `main.go` delegates to it rather than parsing account IDs inline.

### ECS server/client emulation (internal/ecs)

`aws-sso ecs` lets other AWS SDKs/CLIs pick up credentials via the [ECS Task IAM Role credential
endpoint](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
protocol instead of profiles/env vars. `internal/ecs/server` is the HTTP server (with optional TLS
via a self-signed cert stored in the secure store — `GetEcsSslCert`/`GetEcsSslKey`), `internal/ecs/client`
is the client used by `ecs_client_cmd.go`, and `internal/ecs` (top level) holds shared types/security
(bearer-token auth) used by both.

### Mock AWS backend for e2e tests (internal/awsmock)

Everything under `internal/awsmock` is `//go:build e2etests`-gated and never compiles into the
release binary. It's an `httptest.Server`-backed fake of the SSO OIDC, SSO, and STS APIs, routed
by URL path, used exclusively by `cmd/aws-sso/*_e2e_test.go`.

### Logging

All packages log through `internal/logger` (wraps `synfinatic/flexlog`), imported as `log` by
convention. `SwitchLogger("json"|...)` changes output format at runtime; each package typically
has its own thin `logger.go` shim that grabs the shared logger instance for that package's log
lines.

## Conventions

- GPLv3 header block at the top of every `.go` file (`Copyright (c) 2021-2026 Aaron Turner`) —
  copy it verbatim into new files; `make update-copyright` bumps the year range in bulk.
- `golangci-lint` (pinned version, see `.golangci.yaml`) enables `gosec`, `gocyclo`, `dupl`,
  `revive` (with `ID`/`URL`/`JSON`/`URI` as allowed initialisms), `misspell`, `whitespace`,
  `asciicheck` beyond the defaults — run `make lint` before considering a change done.
- `make test-fmt` / `make test-tidy` in CI fail the build on any diff from `gofmt -s` / `go mod tidy`
  — don't leave the tree in a state that would fail these.
- New CLI subcommands: add a `FooCmd` struct + `Run(ctx *RunContext) error` in a new `foo_cmd.go`,
  register it on the `CLI` struct in `main.go` with the appropriate kong group (`login-required`
  commands need SSO auth already established), and set the correct `Auth` level.
