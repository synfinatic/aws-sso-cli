# AWS SSO CLI Changelog

## [Unreleased]

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
