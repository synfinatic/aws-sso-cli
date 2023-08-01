# AWS SSO CLI Changelog

## [v1.11.0] - 2023-07-31

### Bugs

 * Fix `process --profile` flag not working
 * Fix `AccountId` still not zero padding in `list` output

### Changes

 * No longer show usage on error
 * Add `AccountIdStr` as a new field name for the `list` command to pad with zeros
    as appropriate.
 * Change default `ProfileFormat` to `{{ .AccountIdStr }}:{{ .RoleName }}`
 * `ExpiresStr` field name is now `Expires` to match the header
 * `Expires` is now `ExpiresEpoch` as both field name and header
 * `ARN` header is now `Arn` to match the field name

### Deprecated

 * `AccountIdStr` function for `ProfileFormat`.  Use the `.AccountIdStr` variable instead.
 * `ExpiresStr` is now deprecated.  Use `Expires` instead.

## [v1.10.0] - 2023-07-30

### Bugs

 * Fix fish auto-complete helper #472
 * Fix issue where we were not appropriately flushing the roles cache #479
 * Creds with less than 1min remaining now indicate so via `< 1m` rather than empty string
 * We now consistently use `RoleName` as both input and output for the `list` command

### Changes

 * Authentication via your SSO provider no longer uses a Firefox container #486
 * Bump to Go v1.19
 * Bump to golangci-lint v1.52.2
 * AccountId in the `list` command output are now presented with a leading zero(s)
 * Expired IAM credentials are now explictily marked instead of an empty string

### New Features

 * Profiles in ~/.aws/config now include the `region = XXX` option #481
 * Add `FirstTag` support in the config for placing a tag at the top of the select list #445
 * Support `eval` command in Windows PowerShell via Invoke-Expression #188
 * Add support for `--sort` and `--reverse` flags for the `list` command #466

## [v1.9.10] - 2023-02-27

 * Switch to `https` for homebrew submodule
 * Use `homebrew-core` to distribute via brew #458

## [v1.9.9] - 2023-02-25

### Bugs

 * `aws-sso version` no longer requires a valid config file (again)

## [v1.9.8] - 2023-02-25

### Bugs

 * `aws-sso version` no longer requires a valid config file

### Changes

 * Update location for homebrew template file

## [v1.9.7] - 2023-02-25

### Bugs

 * Update golang.org/x/crypto & golang.org/x/crypto/ssh dependencies for security #460
 * Update golang.org/x/sys dependencies for security #461

### Changes

 * Update various dependencies not covered in bugs

## [v1.9.6] - 2022-12-04

### New Features

 * Add `Threads` option to config file
 * Updating the account and role cache now honors the `Threads` option
 * If updating role cache takes > 2 seconds, let users know we're working on it #448

### Bugs

 * `config-profiles` now pads the AccountID in the profile name as described. #446
 * `cache` command no longer queries AWS twice if the cache was expired/invalidated
 * Fix `make fmt` target to use gofmt

### Changes

 * Unexpected AccessToken failure is now considered an error

## [v1.9.5] - 2022-11-13

### New Features

 * Release binaries are now automatically signed via Github Actions

### Changes

 * Now support overriding the timestamp when building via `BUILDINFOS` env var

### Bugs

 * `config-profiles` now always uses the latest list of profiles from AWS #430
 * Specifying the FQDN for the start url hostname now works in the config wizard #434
 * Fix multiple bugs in zsh autocomplete helper
 * Fix problems with a comma in the AccountAlias
 * Fix bug in `aws-sso eval --refresh`

## [v1.9.4] - 2022-09-29

### Bugs

 * Fix macOS amd64 release binary #427
 * Fix role loop detection regression #425

## [v1.9.3] - 2022-09-29

### Changes

 * Update to Golang v1.18
 * Add `ConfigProfilesBinaryPath` option and use $PATH with NIX #410
 * NIX users will use `aws-sso` for `credential_process`

### Bugs

 * `aws-sso config` no longer prompts to backup a config file if it
    doesn't exist.  #402
 * Fix cross-compiling on macOS #407
 * Fix role lookup when defined in the config.yaml #412
 * Fix bug retrieving data from Windows CredStore

## [v1.9.2] - 2022-05-13

### New Features

 * Auto-completion is now context sensitive to the `--sso`, `--account`, and
    `--role` flags and filters results accordingly. #382
 * Add zsh support for shell helpers #360
 * Firefox container name color & icon will be pseudo-randomized if you don't
    specify a Color/Icon tag #392
 * `config` wizard now intelligently selects a default value for
    `ConfigProfilesUrlAction` #387
 * Add support for Granted Containers Firefox plugin #400
 * `UrlAction` and `ConfigProfilesUrlAction` now support `open-url-in-container` and
	`granted-containers`

### Changes

 * Replace `list --profile-prefix` with a more flexible `list --prefix` option #395
 * `FirefoxOpenUrlInContainer` config option has been deprecated

### Bugs

 * Fix broken `completions` for zsh and fish

## [v1.9.1] - 2022-05-09

## Bugs

 * Fix `config` command when user has no `UrlExecCommand` defined #385
 * `console` no longer warns when a role is missing the Color or Icon tag

## [v1.9.0] - 2022-05-08

### New Features

 * Support assuming roles bash without forking a shell _and_ with
    auto-completion support of AWS Profile names. #357
 * Add `completions` command which supports `--install` and `--uninstall` flags
    Please see the [quickstart](
    docs/quickstart.md#enabling-auto-completion-in-your-shell) for more details.
 * Enhanced `list` command with CSV output and basic filtering
 * Add `config` command to re-run through the setup wizard #354
 * Added many more configuration options to the setup wizard
 * `list` command can now generate a CSV via `--csv` flag
 * You can now specify the same StartURL in multiple SSOConfig blocks so you
    can authenticate as different users at the same time.
 * Users can now specify their AWS SSO roles `CacheRefresh` interval instead
    of the hard coded 24hrs. #355

### Changes

 * Added `Profile` to the list of default fields for the `list` command
 * Replaced the command `install-completions` with a more poweful `completions`
 * Renamed the `config` command to update `~/.aws/config` to be `config-profiles`
     which is hopefully more clear
 * `config` command now runs the configuration wizard
 * Deprecated `ConfigUrlAction` option.  Will be automatically upgraded by
    the `aws-sso config` wizard.
 * `ConfigProfilesUrlAction` replaces `ConfigUrlAction`

### Bugs

 * Fixed setup wizard layout to be less ugly and more consistent.
 * `ConsoleDuration` and the `--duration` flag for `aws-sso console` are now
    correctly limited to 12hrs/720min #379
 * Multiple AWS SSO Instances are now properly supported (only) with
    Firefox Containers

## [v1.8.1] - 2022-05-02

### New Features

 * Add Color and Icon support to Firefox Containers #340
 * Auto detect new roles and auto-update ~/.aws/config #341
 * Firefox container support is now handled by guided setup

### Bug Fixes

 * Fix documentation for `UrlExecCommand` config option (was listed as `UrlActionExec`)

### Changes

 * Add `revive` as a linter

## [v1.8.0] - 2022-04-30

### New Features

 * Add support for Firefox Containers for multiple AWS Console sessions #336

### Bug Fixes

 * `console` command now works when `AWS_PROFILE` is set to static creds #332
 * Fix `console` URL redirect to wrong URL #328

## [v1.7.5] - 2022-03-29

### Bug Fixes

 * No longer generate errors for empty History tag in cache #305
 * No longer print the federated console url on errors by default #314
 * Fully delete items from the keyring #320
 * Fixed error when tried to save more than 2.5Kbytes in wincred #308

### New Features

 * Add support for --url-action printurl and exec #303
 * `list` command now prints how long until the AWS SSO session expires #313

### Changes

 * Add additional unit tests
 * Document how using `$AWS_PROFILE` with AWS SSO CLI auto-refreshes credentials #270

## [v1.7.4] - 2022-02-25

### Bug Fixes

 * Fix crash when users have many roles or accounts in AWS SSO
 * Fix crash opening empty json store files
 * Fix crash with AWS AccountIDs in ~/.aws-sso/config.yaml with leading zeros #292

### Changes

 * Add unit tests for AWS SSO API calls
 * No longer read ~/.aws/credentials via AWS Go SDK for slightly better security #280

## [v1.7.3] - 2022-02-10

### Bug Fixes

 * Fix argument parsing with `process` command which broke the command #286

## [v1.7.2] - 2022-02-05

### Bug Fixes

 * Cached AWS SSO AccessToken is sometimes invalid even though it was not expired
    and any calls to SSO were failing.  #279

### Changes

 * `console -P` is now `console -p` to force prompting
 * Update to AWS Go SDK v2

### New Features

 * Support specifying the role to assume via the `-p`/`--profile` flag #268

## [v1.7.1] - 2022-01-16

### Bug Fixes

 * `AWS_SSO` env var is now set with the `eval` and `exec` command #251
 * Fix broken auto-complete for non-Default AWS SSO instances #249
 * Fix incorrect `AWS_SSO_SESSION_EXPIRATION` values #250
 * Remove old config settings that no longer exist #254
 * `cache` command no longer flushes the Expires field for role credentials
    or the role History
 * Auto-guided setup now loads the config so the user defined command is
    successful #260
 * default `list` command will now refresh the cache if necessary

### Changes

 * `flush` now flushes the STS IAM Role credentials first by default #236
 * Guided setup now uses the hostname or FQDN instead of full URL for the SSO StartURL #258

### New Features

 * Add a lot more `ProfileFormat` functions via sprig #244
 * `flush` command gives users more control over what is flushed
 * Add documentation for `SourceIdentity` for AssumeRole operations
 * Add `EnvVarTags` config file option #134

## [v1.7.0] - 2022-01-09

### New Features
 * Add `Via` and `SSO` to possible `list` command output fields
 * Add `SSO` to list of valid ProfileFormat template variables
 * Improve ProfileFormat documentation
 * Add `config` command to manage `~/.aws/config` #157
 * Add Quick Start Guide
 * `console` command now works with any credentials using `$AWS_PROFILE` #234

### Bug Fixes

 * Fix broken FirstItem and StringsJoin ProfileFormat functions
 * Default ProfileFormat now zero-pads the AWS AccountID
 * Fix crash with invalid History tags

### Changes

 * `eval` command now supports `--url-action=print`

## [v1.6.1] - 2021-12-31

### New Features
 * The `Via` role option is now a searchable tag #199
 * The `tags` command now returns the keys in sorted order

### Bug Fixes
 * Consistently pad AccountID with zeros whenever necessary
 * Detect role chain loops using `Via` #194
 * AccountAlias/AccountName tags are inconsistenly applied/missing #201
 * Honor config.yaml `DefaultSSO` #209
 * Setup now defaults to `warn` log level instead of `info` #214
 * `console` command did not know when you are using a non-Default SSO instance #208
 * cache now handles multiple AWS SSO Instances correctly which fixes numerous issues #219

### Changes
 * Reduce number of warnings #205

## [v1.6.0] - 2021-12-24

### Breaking Changes
 * Fix issue with missing colon in parsed/generated Role ARNs for missing AWS region #192

### New Features
 * Setup now prompts for `LogLevel`
 * Suppress bogus warning when saving Role credentials in `wincred` store #183
 * Add support for role chaining using `Via` tag #38
 * Cache file is now versioned for better compatibility across versions of `aws-sso` #195

### Bug Fixes
 * Incorrect `--level` value now correctly tells user the correct name of the flag
 * `exec` command now uses `cmd.exe` when no command is specified

## [v1.5.1] - 2021-12-15

### New Features
 * Setup now prompts for `HistoryMinutes` and `HistoryLimit`

### Bug Fixes
 * Setup now uses a smaller cursor which doesn't hide the character
 * Fix setup bug where the SSO Instance was always called `Default`
 * Setup no longer accepts invalid characters for strings #178
 * Fix error/bell sound on macOS when selecting options during setup #179

## [v1.5.0] - 2021-12-14

### New Features
 * Add `HistoryMinutes` option to limit history by time, not just count #139

### Changes
 * Now use macOS `login` Keychain instead of `AWSSSOCli` #150
 * All secure storage methods now store a single entry instead of multiple entries
 * Replace `console --use-sts` with `console --prompt` #169
 * Improve password prompting for file based keyring #171

### Bug Fixes
 * file keyring will no longer infinitely prompt for new password

## [v1.4.0] - 2021-11-25

### Breaking Changes
 * Standardize on `AWS_SSO` prefix for environment variables
 * Remove `--region` flag for `eval` and `exec` commands
 * `console -use-env` is now `console --use-sts` to be more clear
 * Building aws-sso now requires Go v1.17+

### New Features
 * Add a simple wizard to configure aws-sso on first run if no ~/.aws-sso/config.yaml
	file exists
 * Update interactive selected item color schme to stand our better. #138
 * Add `eval --clear` and `eval --refresh`
 * Add full support for `DefaultRegion` in config.yaml
 * Add `--no-region` flag for `eval and `exec` commands
 * Add `process` command for AWS credential_process in ~/.aws/config #157
 * Add `ConsoleDuration` config option #159
 * Improve documentation of environment variables

### Bug Fixes
 * `exec` now updates the ENV vars of the forked processs rather than our own process
 * `eval` no longer prints URLs #145
 * Will no longer overwrite user defined AWS_DEFAULT_REGION #152
 * Fix bug where cache auto-refresh was not saving the new file, causing future
    runs to not utilize the cache
 * Remove `--duration` option from commands which don't support it
 * `LogLevel` and `UrlAction` in the config yaml now work #161
 * Add more unit tests & fix underlying bugs

## [v1.3.1] - 2021-11-15

 * Fix missing --url-action and  --browser #113
 * Don't print out URL when sending to browser/clipboard for security
 * Escape colon in ARN's for `-a` flag to work around the colon being a
    word delimiter for bash (auto)complete. #135
 * Add initial basic setup if there is a missing config.yaml #131

## [v1.3.0] - 2021-11-14

 * Add report card and make improvements to code style #124
 * Add auto-complete support #12
 * Add golangci-lint support & config file
 * Sort History tag based on time, not alphabetical
 * History entries now have how long since it was last used #123

## [v1.2.3] - 2021-11-13

 * Add support for tracking recently used roles via History tag for exec & console #29
 * Continue to improve unit tests
 * Fix bugs in `tags` command when using -A or -R to filter results
 * Fix missing tags when not defining roles in config.yaml #116
 * Fix bad Linux ARM64/AARCH64 rpm/deb packages with invalid binaries

## [v1.2.2] - 2021-11-11

 * Add `AccountAlias` and `Expires` to list of fields that can be displayed via
    the `list` command
 * `AccountAlias` replaces `AccountName` in the list of default fields for `list`
 * Add RPM and DEB package support for Linux on x86_64 and ARM64 #52

## [v1.2.1] - 2021-11-03

 * Add customizable color support #79
 * Simplify options for handling URLs and refactor internals #82
 * Rework how defaults are handled/settings loaded
 * Remove references to `duration` in config which don't do anything
 * Add additional config file options:
	- UrlAction
	- LogLevel
	- LogLines
	- DefaultSSO
 * Replace `--print-url` with `--url-action` #81
 * Add support for `DefaultRegion` in config file  #30
 * `console` command now supports `--region`
 * `list` command now reports expired and has constant sorting of roles #71
 * Fix bug where STS token creds were cached, but not reused.
 * `list -f` now sorts fields
 * Use cache for tracking when STS tokens expire
 * `exec` command now ignores arguments intended for the command being run #93
 * Remove `-R` as a short version of `--sts-refresh` to avoid collision with exec role #92
 * Fix finding $HOME directory on Windows and make GetHomePath() cross platform #100
 * Fix issue with AWS AccountID's with leading zeros.  #96
 * Optionally delete STS credentials from secure store cache #104
 * Add support for Brew #52

## [v1.2.0] - 2021-10-29

 * `console` command now can use ENV vars via --use-env #41
 * Fix bugs in `console` with invalid CLI parsing
 * Tag keys and values are now separate choices #49
 * Auto-complete options are now sorted
 * Started writing some unit tests
 * Do SSO authentication after role selection to improve performance
    even when we have cached creds
 * Add support for `AWS_SSO_PROFILE` env var and `ProfileFormat` in config #48
 * Auto-detect when local cache it out of date and refresh #59
 * Add support for `cache` command to force refresh AWS SSO data
 * Add support for `renew` command to refresh AWS credentials in a shell #63
 * Rename `--refresh` flag to be `--sts-refresh`
 * Remove `--force-refresh` flag from `list` command
 * Add role metadata when selecting roles #66

## [v1.1.0] - 2021-08-22

 * Move role cache data from SecureStore into json CacheStore #26
 * `exec` command will abort if a conflicting AWS Env var is set #27
 * Add `time` command to report how much time before the current STS token expires #28
 * Add support for printing Arn in `list` #33
 * Add `console` support to login to AWS Console with specified role #36
 * `-c` no longer is short flag for `--config`

## [v1.0.1] - 2021-07-18

 * Add macOS/M1 support
 * Improve documentation
 * Fix `version` output
 * Change `exec` prompt to work around go-prompt bug
 * Typing `exit` now exits without an error
 * Add help on how to exit via `exit` or ctrl-d

## [v1.0.0] - 2021-07-15

Initial release

[Unreleased]: https://github.com/synfinatic/aws-sso-cli/compare/v1.11.0...main
[v1.11.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.10.0
[v1.10.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.10
[v1.9.10]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.9
[v1.9.9]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.9
[v1.9.8]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.8
[v1.9.7]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.7
[v1.9.6]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.6
[v1.9.5]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.5
[v1.9.4]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.4
[v1.9.3]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.3
[v1.9.2]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.2
[v1.9.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.1
[v1.9.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.9.0
[v1.8.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.8.1
[v1.8.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.8.0
[v1.7.5]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.7.5
[v1.7.4]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.7.4
[v1.7.3]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.7.3
[v1.7.2]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.7.2
[v1.7.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.7.1
[v1.7.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.7.0
[v1.6.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.6.1
[v1.6.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.6.0
[v1.5.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.5.1
[v1.5.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.5.0
[v1.4.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.4.0
[v1.3.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.3.1
[v1.3.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.3.0
[v1.2.3]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.2.3
[v1.2.2]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.2.2
[v1.2.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.2.1
[v1.2.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.2.0
[v1.1.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.1.0
[v1.0.1]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.0.1
[v1.0.0]: https://github.com/synfinatic/aws-sso-cli/releases/tag/v1.0.0
