# aws-sso Commands

## Common Flags

* `--help`, `-h` -- Builtin and context sensitive help
* `--browser <path>`, `-b` -- Override default browser to open AWS SSO URL (`$AWS_SSO_BROWSER`)
* `--config <file>` -- Specify alternative config file (`$AWS_SSO_CONFIG`)
* `--level <level>`, `-L` -- Change default log level: [error|warn|info|debug|trace]
* `--lines` -- Print file number with logs
* `--sso <name>`, `-S` -- Specify non-default AWS SSO instance to use (`$AWS_SSO`)

## Commands

### cache

AWS SSO CLI caches information about your AWS Accounts, Roles and Tags for
better perfomance.  By default it will refresh this information after 24
hours, but you can force this data to be refreshed immediately.

Cache data is also automatically updated anytime the `config.yaml` file is
modified.

Flags:

* `--no-config-check` -- Disable automatic updating of `~/.aws/config`
* `--threads <int>` -- Number of threads to use with AWS (default: 5)

---

### console

Console generates a URL which will grant you access to the AWS Console in your
web browser.  The URL can be sent directly to the browser (default), printed
in the terminal or copied into the Copy & Paste buffer of your computer.

**Note:** Normally, you can only have a single active AWS Console session at
a time, but multiple session are supported via the [open-url-in-container](
config.md#open-url-in-firefox-container) configuration option.

Flags:

* `--duration <minutes>`, `-d` -- AWS Session duration in minutes (default 60)
* `--prompt`, `-P` -- Force interactive prompt to select role
* `--region <region>`, `-r` -- Specify the `$AWS_DEFAULT_REGION` to use
* `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
* `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
* `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)
* `--profile <profile>`, `-p` -- Name of AWS Profile to assume
* `--url-action`, `-u` -- How to handle URLs for your SSO provider
* `--sts-refresh` -- Force refresh of STS Token Credentials

The generated URL is good for 15 minutes after it is created.

The common flag `--url-action` is used both for AWS SSO authentication as well as
what to do with the resulting URL from the `console` command.

Priority is given to:

* `--prompt`
* `--profile`
* `--arn` (`$AWS_SSO_ROLE_ARN`)
* `--account` (`$AWS_SSO_ACCOUNT_ID`) and `--role` (`$AWS_SSO_ROLE_NAME`)
* `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` environment variables
* `AWS_PROFILE` environment variable (works with both SSO and static profiles)
* Prompt user interactively

---

### credentials

Generate static credentials in the format for [~/.aws/credentials](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html#cli-configure-files-format).

This command will expose your temporary AWS IAM credentials in clear text which can be a security issue,
and is not recommended except for cases where going through the AWS Identity Center web-based authentication
workflow is not possible.  The most common example of this would be integrating with Docker and needing
multiple IAM Roles.  Most use cases are better served by using the [setup-profiles](#setup-profiles) command or
passing in IAM credentials via [environment variables](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).

Flags:

* `--file <path>`, `-f` -- Specify the file to generate.  Default is to print to STDOUT ($AWS_SHARED_CREDENTIALS_FILE).
* `--append`, `-a` -- Append to the file instead of overwriting it.
* `--profile <profile>,...`, `-p` -- One or more profiles to include in the output.
* `--sts-refresh` -- Force refresh of STS Token Credentials

**Note:** This command honors the same [$AWS_SHARED_CREDENTIALS_FILE](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html)
that is supported by the AWS SDK to load credentials.  Since these credentials are temporary, it is
_strongly_ discouraged that users set this to `~/.aws/credentials`, but use a temporary file instead.

---

### ecs

[ecs commands](ecs-commands.md)

---

### eval

Generate a series of `export VARIABLE=VALUE` lines suitable for sourcing into your
shell.  Allows obtaining new AWS credentials without starting a new shell.  Can be
used to refresh existing AWS credentials or by specifying the appropriate arguments.

Suggested use (bash): `eval $(aws-sso eval <args>)`

or if you are using [VSCode environment variables](
https://code.visualstudio.com/remote/advancedcontainers/environment-variables#_option-2-use-an-env-file)
you can write the variable to a file:

`aws-sso eval <args> >~/.devcontainer/devcontainer.env`

Shells supported by `eval`:

* bash
* fish
* zonsh
* zsh
* Windows PowerShell

Flags:

* `--arn <arn>`, `-a` -- ARN of role to assume
* `--account <account>`, `-A` -- AWS AccountID of role to assume (requires `--role`)
* `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`)
* `--profile <profile>`, `-p` -- Name of AWS Profile to assume
* `--clear`, `-c` -- Generate "unset XXXX" commands to clear the environment
* `--no-region` -- Do not set the [AWS_DEFAULT_REGION](config.md#defaultregion) from config.yaml
* `--refresh` -- Refresh current IAM credentials

Priority is given to:

* `--refresh` (Uses `$AWS_SSO_ROLE_ARN`)
* `--profile`
* `--arn`
* `--account` and `--role`

**Note:** The `eval` command only honors the `$AWS_SSO_ROLE_ARN` in the context
of the `--refresh` flag.  The `$AWS_SSO_ROLE_NAME` and `$AWS_SSO_ACCOUNT_ID`
are always ignored.

**Note:** Using `--url-action=print` is supported, but you must be able to see the output
of _STDERR_ to see the URL to open.

**Note:** The `eval` command is not supported under Windows CommandPrompt or PowerShell.

See [Environment Variables](#environment-variables) for more information about
what varibles are set.

#### Windows PowerShell

Getting Windows PowerShell to work requires a slightly different invocation than
bash/zsh/etc:

`aws-sso eval <args> | Out-String | Invoke-Expression`

But other than that, it works the same way.

---

### exec

Exec allows you to execute a command with the necessary [AWS environment variables](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).  By default,
if no command is specified, it will start a new interactive shell so you can run multiple
commands.

Flags:

* `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
* `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
* `--env`, `-e` -- Use existing ENV vars generated by AWS SSO to generate a URL
* `--role <role>`, `-R` -- Name of AWS Role to assume (`$AWS_SSO_ROLE_NAME`)
* `--profile <profile>`, `-p` -- Name of AWS Profile to assume
* `--no-region` -- Do not set the [AWS_DEFAULT_REGION](config.md#defaultregion) from config.yaml
* `--sts-refresh` -- Force refresh of STS Token Credentials
* `--ignore-env`, `-i` -- Force execution even if AWS_* environment variables are set

Arguments: `[<command>] [<args> ...]`

Priority is given to:

* `--profile`
* `--arn` (`$AWS_SSO_ROLE_ARN`)
* `--account` (`$AWS_SSO_ACCOUNT_ID`) and `--role` (`$AWS_SSO_ROLE_NAME`)
* Prompt user interactively

You can not run `exec` inside of another `exec` shell or when the `$AWS_*` environment
variables are set unless you pass in `--ignore-env`.

See [Environment Variables](#environment-variables) for more information about
what varibles are set.

---

### process

Process allows you to use AWS SSO as an [external credentials provider](
https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes)
with profiles defined in `~/.aws/config`.

Flags:

* `--arn <arn>`, `-a` -- ARN of role to assume
* `--account <account>`, `-A` -- AWS AccountID of role to assume
* `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`)
* `--profile <profile>`, `-p` -- Name of AWS Profile to assume
* `--sts-refresh` -- Force refresh of STS Token Credentials

Priority is given to:

* `--profile`
* `--arn`
* `--account` and `--role`

**Note:** The `process` command does not honor the `$AWS_SSO_ROLE_ARN`,
`$AWS_SSO_ACCOUNT_ID`, or `$AWS_SSO_ROLE_NAME` environment variables.

**Note:** Due to a limitation of the AWS tooling, setting `--url-action print`
will cause an error.

---

### list

List will list all of the AWS Roles you can assume with the metadata/tags
available to be used for interactive selection with `exec`.  You can control
which fields are printed by specifying the field names as arguments.

Flags:

* `--list-fields`, `-f` -- List the available fields to print
* `--prefix <FieldName>=<Prefix>`, `-P` -- Filter results by the given field
    value & prefix value
* `--csv` -- Generate results in CSV format
* `--sort <FieldName>`, `-s` -- Sort results by the provided field name
* `--reverse` -- Reverse the sort order

Arguments: `[<field> ...]`

The arguments are a list of fields to display in the report.  Overrides the
defaults and/or the specified [ListFields](config.md#ListFields) in the
`config.yaml`.

Default fields:

* `AccountIdPad`
* `AccountAlias`
* `RoleName`
* `Expires`

**Note:** Sorting for `AccountIdPad` and `Expires` is done via their respective
`AccountId` and `ExpiresEpoch` integer values.  Expired entries are considered
to be very large.  All other fields are sorted alphabetically and in a
case-sensitive manner.

---

### login

Login via AWS IAM Identity Center (AWS SSO) and retrieve a security token
used to fetch IAM Role credentials.  As of `aws-sso` v2.x this is required
_unless_ you enable [AutoLogin](config.md#autologin).

When you login, `aws-sso` will attempt to refresh your cache of IAM Roles
per the [CacheRefresh](config.md#cacherefresh) setting.

Flags:

* `--no-config-check` -- Disable automatic updating of `~/.aws/config`
* `--url-action`, `-u` -- How to handle URLs for your SSO provider
* `--sts-refresh` -- Force refresh of STS Token Credentials
* `--threads <int>` -- Number of threads to use with AWS (default: 5)

---

### logout

Invalidates the AWS Identity Center AccessToken (used to fetch new IAM Credentials)
for the selected SSO instance and removes all IAM Role Credentials cached in the `aws-sso` secure store.

---

### setup completions

Configures your appropriate shell configuration file to add auto-complete
and [Shell Helpers](#shell-helpers) functionality for commands, flags and
options. Must restart your shell for this to take effect.

For more information about this feature, please read [the quickstart](
quickstart.md#enabling-auto-completion-in-your-shell).

Flags:

* `--source` -- Print out the completions for sourcing into the current shell
* `--install` -- Install the new v1.9+ shell completions scripts
* `--uninstall` -- Uninstall the new v1.9+ shell completions scripts
* `--shell <shell>` -- Override the detected shell
* `--shell-script <file>` -- Override the default shell script file to modify

---

### setup ecs

See the [setup ecs](ecs-commands.md#setup-ecs) commands in the ECS Server command documentation.

---

### setup profiles

Modifies the `~/.aws/config` file to contain a [named profile](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-using-profiles)
for every role accessible via AWS SSO CLI.

Flags:

* `--diff` -- Print a diff of changes to the config file instead of modifying it
* `--print` -- Print profile entries instead of modifying config file
* `--force` -- Write a new config file without prompting
* `--aws-config` -- Override path to `~/.aws/config` file

By default, each profile is named according to the [ProfileFormat](
config.md#profileformat) config option or overridden by the user defined
[Profile](config.md#profile) option on a role by role basis.

For each profile generated, it will specify a [list of settings](
https://docs.aws.amazon.com/sdkref/latest/guide/settings-global.html) as defined
by the [ConfigVariables](config.md#configvariables) setting in the
`~/.aws-sso/config.yaml`.

For more information on this feature, [read the Quickstart Guide](
quickstart.md#using-the-aws_profile-variable).

Unlike with other ways to use AWS SSO CLI, the AWS IAM STS credentials will
_automatically refresh_.  This means, if you do not have a valid AWS SSO token,
you will be prompted to authentiate via your SSO provider and subsequent
requests to obtain new IAM STS credentials will automatically happen as needed.

**Note:** You should run this command _after_ [aws-sso cache](#cache) any time
your list of AWS roles changes in order to update the `~/.aws/config` file
or enable [AutoConfigCheck](config.md#autoconfigcheck).

**Note:** It is important that you do _NOT_ remove the `# BEGIN_AWS_SSO_CLI` and
`# END_AWS_SSO_CLI` lines from your config file!  These markers are used to track
which profiles are managed by AWS SSO CLI.

**Note:** This command does not auto-refresh the list of cached roles, so if they
have recently changed you should run `aws-sso cache` first.

---

### setup wizard

Allows you to run through the configuration wizard and update your AWS SSO CLI
config file (`~/.aws-sso/config.yaml`).   By default, it only does a very basic
configuration to get started with.  The `--advanced` flag prompts for more
settings and is useful for taking advantage of some of the new settings if
you've upgraded from a previous version!

Flags:

* `--advanced` -- Prompts for many more config options

---

### tags

Tags dumps a list of AWS SSO roles with the available metadata tags.

Flags:

* `--account <account>` -- Filter results by AccountId
* `--role <role>` -- Filter results by Role Name

By default the following key/values are available as tags to your roles:

* `AccountID` -- AWS Account ID
* `Role` -- AWS Role Name
* `Email` -- Email address of root account associated with the AWS Account
* `AccountName` -- Account Name for any role defined in config (see below)
* `AccountAlias` --- AWS Account Alias defined by account administrator
* `History` -- Tag tracking if this role was recently used.  See `HistoryLimit`
        in config.

---

### time

Print a string containing the number of hours and minutes that the current
AWS Role's STS credentials are valid for in the format of `HHhMMm`

**Note:** This command is only useful when you have STS credentials configured
in your shell via [eval](#eval) or [exec](#exec).

## Environment Variables

### Honored Variables

The following environment variables are honored by `aws-sso`:

* `AWS_CONFIG_FILE` -- Override default path to `~/.aws/config` file
* `AWS_SSO_FILE_PASSWORD` -- Password to use with the `file` SecureStore.
* `AWS_SSO_CONFIG` -- Specify an alternate path to the `aws-sso` config file.
* `AWS_SSO_BROWSER` -- Override default browser for AWS SSO login.
* `AWS_SSO` -- Override default AWS SSO instance to use.
* `AWS_SSO_ROLE_NAME` -- Used for `--role`/`-R` with some commands.
* `AWS_SSO_ACCOUNT_ID` -- Used for `--account`/`-A` with some commands.
* `AWS_SSO_ROLE_ARN` -- Used for `--arn`/`-a` with some commands and with.
     `eval --refresh`.
* `AWS_SSO_FIELD_SORT` -- Used by `list` command to select which field to sort by.
* `AWS_SSO_FIELD_SORT_REVERSE` -- Used to reverse the `list` sort order.  Set to `1` to enable.

The `file` SecureStore will use the `AWS_SSO_FILE_PASSWORD` environment
variable for the password if it is set. (Not recommended.)

Additionally, `$AWS_PROFILE` is honored via the standard AWS tooling when using
the [setup-profiles](#setup-profiles) command to manage your `~/.aws/config` file.

---

### Managed Variables

The following [AWS environment variables](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
are automatically set by `aws-sso`:

* `AWS_ACCESS_KEY_ID` -- Authentication identifier required by AWS
* `AWS_SECRET_ACCESS_KEY` -- Authentication secret required by AWS
* `AWS_SESSION_TOKEN` -- Authentication secret required by AWS
* `AWS_DEFAULT_REGION` -- Region to use AWS with (will never override an
    existing value)

The following environment variables are specific to `aws-sso`:

* `AWS_SSO_ACCOUNT_ID` -- The AccountID for your IAM role
* `AWS_SSO_ROLE_NAME` -- The name of the IAM role
* `AWS_SSO_ROLE_ARN` -- The full ARN of the IAM role
* `AWS_SSO_SESSION_EXPIRATION`  -- The date and time when the IAM role
    credentials will expire in [RFC3339 format](https://datatracker.ietf.org/doc/html/rfc3339)
* `AWS_SSO_DEFAULT_REGION` -- Tracking variable for `AWS_DEFAULT_REGION`
* `AWS_SSO_PROFILE` -- User customizable varible using the
    [ProfileFormat](config.md#profileformat) template
* `AWS_SSO` -- AWS SSO instance name

**Note:** AWS SSO does _NOT_ set `$AWS_PROFILE` to avoid problems with the AWS tooling
and SDK.

## Shell Helpers

These are optional helper functions installed in your shell as part of the
[setup-completions](#setup-completions) command.  To install these helper functions,
please see the [quickstart](quickstart.md) page.

**Important:** Unlike the commands above, these are standalone shell functions
and you should _NOT_ prefix them with `aws-sso`.

By default, these commands uses your default AWS SSO instance, but you can
override this by first exporting `AWS_SSO` to the value you want to use.

If you want to pass specific args to `aws-sso-profile` you can use the
`$AWS_SSO_HELPER_ARGS` environment variable.  If nothing is set, then
`--level error` is used.

Currently the following shells are supported:

* [bash](https://github.com/synfinatic/aws-sso-cli/blob/main/internal/helper/bash_profile.sh)
* [zsh](https://github.com/synfinatic/aws-sso-cli/blob/main/internal/helper/zshrc.sh)
* [fish](https://github.com/synfinatic/aws-sso-cli/blob/main/internal/helper/aws-sso.fish)

**Note:** `zsh` completion requires you to have the following lines set
before the AWS SSO completions:

```bash
autoload -Uz +X compinit && compinit
autoload -Uz +X bashcompinit && bashcompinit
```

**Note:** Please reach out if you can help with adding support for your
favorite shell!

---

### aws-sso-profile

This shell command enables you to assume an AWS SSO role by the profile name
_in the current shell and with auto-complete functionality_.  Basically it is a
wrapper around `eval $(aws-sso eval --profile XXXX)` but with auto-complete.

This command will export the same [environment variables](#managed-variables)
as the [eval](#eval) command.

**Note:** This command will overwrite existing environment variables, but will
refuse to run if `AWS_PROFILE` is set.

---

### aws-sso-clear

Clears all the [managed environment variables](#managed-variables) in your
current shell set by `aws-sso-profile` or by running `eval $(aws-sso env ...)`.
