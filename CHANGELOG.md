# AWS SSO CLI Changelog

## [Unreleased]

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
