# AWS SSO CLI Changelog

## [Unreleased]

### New Features
 * Add `HistoryMinutes` option to limit history by time, not just count #139

### Changes
 * Now use macOS `login` Keychain instead of `AWSSSOCli` #150
 * All secure storage methods now store a single entry instead of multiple entries
 * Replace `console --use-sts` with `console --prompt` #169
 * Improve password prompting for file based keyring #171

### Bug Fixes
 * file keyring will no longer infinitely prompt for new password

## [v1.4.0]

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
[Unreleased]: https://github.com/synfinatic/aws-sso-cli/compare/v1.4.0...main
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
