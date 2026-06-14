# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

## Commands

```bash
# Build for current platform
make

# Run tests (vet + unit tests + lint + homebrew smoke test)
make test

# Run unit tests only
make unittest

# Run integration tests against mock AWS HTTP servers
make integration

# Run a single test
go test -v -run TestName ./internal/sso/...

# Lint (requires golangci-lint matching GOLANGCI_LINT_VERSION in Makefile)
make lint

# Install correct golangci-lint version
make lint-install

# Format code
make fmt

# Run go vet
make vet

# Build and run with args
make run PROGRAM_ARGS="list"

# Full precheck (runs everything CI checks)
make precheck
```

Every PR must have an entry in `CHANGELOG.md` — CI checks for this.

## Architecture

This is a single Go binary (`aws-sso`) that manages AWS IAM Identity Center (SSO) credentials.
The main entry point is `cmd/aws-sso/main.go`, which uses [Kong](https://github.com/alecthomas/kong)
for CLI parsing and [kongplete](https://github.com/willabides/kongplete) for shell completions.

### Command Layer (`cmd/aws-sso/`)

One file per subcommand (e.g., `eval_cmd.go`, `list_cmd.go`). Each command struct implements a
`Run(*RunContext) error` method. The `RunContext` carries:

- `Settings` — unified config + cache (the central object)
- `Store` — the active `SecureStorage` implementation
- `Auth` — whether the command needs SSO auth (`AUTH_REQUIRED`/`AUTH_SKIP`/`AUTH_NO_CONFIG`)
- `Ctx` — a `context.Context` created via `signal.NotifyContext` in `main()`; cancelled on
  SIGINT/SIGTERM

Commands signal their auth requirement via `AfterApply(*RunContext)`, which Kong calls after flag
parsing.

### Core SSO Layer (`internal/sso/`)

- **`settings.go`** — `Settings` struct loaded from `~/.aws-sso/config.yaml` via
  [koanf](https://github.com/knadh/koanf). Holds `SSOConfig` map (one entry per SSO instance),
  user preferences, and a pointer to the `Cache`.
- **`cache/`** — `Cache` struct persisted to a JSON file. Contains `SSOCache` per SSO instance,
  which holds the role/account tree (`Roles`), history, and config hash for detecting staleness.
- **`roles/`** — `Roles`, `AWSAccount`, `AWSRole`, `AWSRoleFlat` data structures. `AWSRoleFlat`
  is a denormalized view used for display and template rendering (profile names use Go templates
  with [sprig](https://github.com/Masterminds/sprig)).
- **`auth/`** — `AWSSSO` struct that wraps AWS SDK calls to fetch role credentials. Handles the
  SSO → STS credential exchange.
- **`oidc/`** — OIDC token acquisition (device code flow and PKCE/authorization code flow). Calls
  `storage.SecureStorage` to persist `RegisterClientData` and `CreateTokenResponse`.
- **`config/`** — `SSOConfig` type (per-SSO-instance config: StartUrl, SSORegion, accounts, tags).

### Secure Storage (`internal/storage/`)

`SecureStorage` interface (`secure_store.go`) abstracts credential persistence. Two implementations:
- **`KeyringStore`** (`keyring.go`) — uses [99designs/keyring](https://github.com/99designs/keyring)
  (OS keychain, secret service, etc.)
- **`JsonStore`** (`json_store.go`) — encrypted JSON file fallback

All `Save*` and `Delete*` methods on `SecureStorage` take `context.Context` as their first
argument; `Get*` methods do not. `KeyringStore` uses `FlockBlockerWithCtx` with a 30-second
timeout per lock acquisition; `JsonStore` accepts but ignores the context.

Stored data types: `RegisterClientData`, `CreateTokenResponse`, `RoleCredentials`,
`StaticCredentials`, ECS bearer token, ECS SSL keypair.

### ECS Server (`internal/ecs/`)

HTTP server that exposes AWS credentials to containers via the
[ECS task credential endpoint protocol](https://synfinatic.github.io/aws-sso-cli/latest/ecs-server/).
The `server/` subdirectory contains the server implementation; `client/` contains the client used
by `ecs_client_cmd.go`. Auth via bearer token stored in `SecureStorage`.

### Supporting Packages

- **`internal/awsconfig/`** — reads/writes `~/.aws/config` and `~/.aws/credentials`
- **`internal/awsparse/`** — ARN parsing, AccountID conversion (int64 ↔ zero-padded string)
- **`internal/config/`** — config path utilities (`ConfigDir`, `ConfigFile`, `JsonStoreFile`,
  `InsecureCacheFile`)
- **`internal/logger/`** — logging wrapper around [flexlog](https://github.com/synfinatic/flexlog)/slog;
  initializes default stderr logger at warn level
- **`internal/predictor/`** — shell completion data sources (account IDs, role names, ARNs, AWS
  partitions)
- **`internal/tags/`** — tag filtering logic
- **`internal/uri/`** — URL action dispatch (open browser, print, clipboard, etc.)
- **`internal/ui/`** — terminal UI helpers
- **`internal/prompt/`** — interactive prompt wrappers (go-prompt, promptui)
- **`internal/timeutils/`** — time parsing/formatting utilities
- **`internal/fileutils/`** — file locking and path utilities
- **`internal/helper/`** — miscellaneous helpers

### Config Loading

Config uses koanf with layered loading: defaults (`DEFAULT_CONFIG` map in `settings.go`) → YAML
file. The YAML key is controlled by `koanf` struct tags, not `yaml` tags, so the on-disk field
names may differ from struct field names.

### Linting

golangci-lint version is pinned in `GOLANGCI_LINT_VERSION` in the Makefile (currently v2.10.1,
using the golangci-lint v2 config format). The config (`.golangci.yaml`) enables: `asciicheck`,
`dupl`, `gocyclo`, `gosec`, `misspell`, `revive`, `whitespace`. The `revive` linter enforces
specific acronym casing (`ID`, `URL`, `JSON`, `URI`) via `var-naming` rules. The `gofmt`
formatter is also enabled.

## Additional Instructions

- Do not use `go build` to build the program, use `make` instead.
- Always run `make test` after any change to validate
- Use TDD - test driven development when adding any new features/functionality
- When writing plans to a file, wrap long lines at 100 characters wide
