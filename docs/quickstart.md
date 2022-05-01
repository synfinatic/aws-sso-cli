# AWS SSO CLI Quick Start & Installation Guide

## Installation

 * Option 1: [Download binary](https://github.com/synfinatic/aws-sso-cli/releases)
    1. Copy to appropriate location and `chmod 755`
 * Option 2: [Download RPM or DEB package](https://github.com/synfinatic/aws-sso-cli/releases)
    1. Use your package manager to install (Linux only)
 * Option 3: Install via [Homebrew](https://brew.sh)
	1. Run `brew tap synfinatic/aws-sso-cli`
	1. Run `brew install aws-sso-cli`
 * Option 4: Build from source:
    1. Install [GoLang](https://golang.org) v1.17+ and GNU Make
    1. Clone this repo
    1. Run `make` (or `gmake` for GNU Make)
    1. Your binary will be created in the `dist` directory
    1. Run `make install` to install in /usr/local/bin

Note that the release binaries and packages are not officially signed at this time so
systems may generate warnings.

## Configuration

AWS SSO CLI includes a simple setup wizard to aid in configuration.  This
wizard will automatically run anytime you run `aws-sso` and have a missing
`~/.aws-sso/config.yaml` file and it will ask the following questions:

 * SSO Instance Name ([DefaultSSO](config.md#defaultsso))
 * SSO Start URL ([StartUrl](config.md#starturl))
 * AWS SSO Region ([SSORegion](config.md#ssoregion))
 * Default region for connecting to AWS ([DefaultRegion](config.md#defaultregion))
 * Default action to take with URls ([UrlAction](config.md#browser--urlaction))
 * Maximum number of History items to keep ([HistoryLimit](config.md#historylimit))
 * Number of minutes to keep items in History ([HistoryMinutes](config.md#historyminutes))
 * Log Level ([LogLevel](config.md#loglevel--loglines))

For more information about configuring `aws-sso` read the
[configuration guide](config.md).

## Auto-Complete

After the guided setup, it is worth running:

`aws-sso install-completions`

to [install tab autocomplete](config.md#install-completions) for your shell.

## Integrating AWS SSO CLI with `$AWS_PROFILE`

The easiest way to use AWS SSO CLI is to integrate it with your existing
`~/.aws/config` config file.  This allows you to consistently manage which AWS
Role to use [named profiles](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html).

Run: `aws-sso config --open [open|clip|exec]`

This will add the following lines (example) to your `~/.aws/config` file:

```
# BEGIN_AWS_SSO

[profile Name1]
credential_process = /usr/local/bin/aws-sso -u <open> process --sso <name> --arn <arn1>

[profile Name2]
credential_process = /usr/local/bin/aws-sso -u <open> process --sso <name> --arn <arn2>

# END_AWS_SSO
```

For more information about this feature, see [the documentation](../README.md#config)
and the [ConfigVariables](config.md#configvariables) config file setting to set
[AWS global config file settings](
https://docs.aws.amazon.com/sdkref/latest/guide/settings-global.html).

### Using AWS SSO CLI with `$AWS_PROFILE`

Once your `~/.aws/config` file has been modified as described above, you can
access any AWS SSO role the same way you would access a traditional role defined
via AWS API keys: set the `$AWS_PROFILE` environment variable to the name of
the profile.

The only difference is that your API keys are managed via AWS SSO and always
safely stored encrypted on disk!

```bash
$ export AWS_PROFILE=<name>
$ aws sts get-caller-identity
$ aws s3api list-buckets
```

or for a single command:

```bash
$ AWS_PROFILE=<name> aws sts get-caller-identity
```

Note that every time the `aws` tool or your code makes a request for the API
credentials, it is calling `aws-sso`.  The first time it does this for a role,
`aws-sso` will talk to AWS STS to get some credentials and then cache the result.
This may (or may not) require human inteaction to authenticate via your SSO
provider.  Future calls will then use the cached STS credentials until they
expire or are [flushed](../README.md#flush).

### Customize your `$AWS_PROFILE` names

By default, each AWS role is given an `$AWS_PROFILE` name matching the
`<AccountID>:<RoleName>`.  You can change this value in one of two ways:

 1. Set the [ProfileFormat](config.md#profileformat) variable to change
	the automatically generated value for each role to a template of your
	choice.
 1. Set the [Profile](config.md#profile) value for the individual role
	to any value you wish.

### Pros and Cons

Pros:

 * Don't need to learn any new commands once you have it setup
 * Is a more consistent user experience when switching from static API keys

Cons:

 * Does not support printing URLs to the console for the user to paste into a browser
 * Can be difficult to manage with lots of Accounts/Roles

## Other ways to use AWS SSO CLI

There are other ways to use AWS SSO CLI which do not involve modifying
`~/.aws/config` and setting `$AWS_PROFILE`.  These work great if you are only
using AWS SSO to manage access to your roles.

### Spawn a new shell

This uses the [exec](../README.md#exec) command to create a new shell with the
necessary AWS STS environment variables set to access AWS.

Pros:

 * Allows picking a role via CLI arguments or via the interactive search feature
 * Unlike with the config/`$AWS_PROFILE` integration, it supports opening URLs
    in your browser, printing or copying to your clipboard
 * Allows you to quickly access any role in any account without remembering the
    exact `$AWS_PROFILE` name

Cons:

 * Can be confusing when you start nesting shells inside of each other
 * Can avoid the shell-in-a-shell bit, but is harder to use because every command must
    be prefixed with `aws-sso ...`

### Configure your current shell

This uses the [eval](../README.md#eval) command to modify the current shell with the
necessary AWS STS environment variables.

Pros:

 * Less confusing to manage your shell-in-a-shell situation that can happen with `exec`
 * Unlike with the config/`$AWS_PROFILE` integration, it supports opening URLs in your
    browser, printing or copying to your clipboard

Cons:

 * Not able to use the interactive search feature found in `exec`
 * Auto-complete functionality doesn't work because bash/etc get confused by the
    `eval $(aws-sso ...)` bit
