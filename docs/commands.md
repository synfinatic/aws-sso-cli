# Running aws-sso

 * [Common Flags](#common-flags)
 * [Commands](#commands)
    * [cache](#cache) -- Force reload of cached AWS SSO role info and config.yaml
    * [config](#config) -- Update ~/.aws/config with AWS SSO profiles from the cache
    * [console](#console) -- Open AWS Console using specified AWS role/profile
    * [eval](#eval) -- Print AWS environment vars for use with `eval $(aws-sso eval ...)`
    * [exec](#exec) -- Execute command using specified IAM role in a new shell
    * [flush](#flush) -- Flush AWS SSO/STS credentials from cache
    * [list](#list) -- List all accounts / roles (default command)
    * [process](#process) -- Generate JSON for `credential_process` in ~/.aws/config
    * [tags](#tags) -- List tags
    * [time](#time) -- Print how much time before current STS Token expires
    * [version](#version) -- Print version and exit
    * [install-completions](#install-completions) -- Install shell completions
 * [Environment Variables](#environment-variables)


## Common Flags

 * `--help`, `-h` -- Builtin and context sensitive help
 * `--browser <path>`, `-b` -- Override default browser to open AWS SSO URL (`$AWS_SSO_BROWSER`)
 * `--config <file>` -- Specify alternative config file (`$AWS_SSO_CONFIG`)
 * `--level <level>`, `-L` -- Change default log level: [error|warn|info|debug|trace]
 * `--lines` -- Print file number with logs
 * `--url-action`, `-u` -- How to handle URLs for your SSO provider
 * `--sso <name>`, `-S` -- Specify non-default AWS SSO instance to use (`$AWS_SSO`)
 * `--sts-refresh` -- Force refresh of STS Token Credentials

## Commands

### console

Console generates a URL which will grant you access to the AWS Console in your
web browser.  The URL can be sent directly to the browser (default), printed
in the terminal or copied into the Copy & Paste buffer of your computer.

**Note:** Normally, you can only have a single active AWS Console session at
a time, but multiple session are supported via the [FirefoxOpenUrlInContainer](
docs/config.md#firefoxopenurlincontainer) configuration option.

Flags:

 * `--region <region>`, `-r` -- Specify the `$AWS_DEFAULT_REGION` to use
 * `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
 * `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
 * `--duration <minutes>`, `-d` -- AWS Session duration in minutes (default 60)
 * `--prompt`, `-P` -- Force interactive prompt to select role
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)
 * `--profile <profile>`, `-p` -- Name of AWS Profile to assume

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

### config

Modifies the `~/.aws/config` file to contain a [named profile](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html)
for every role accessible via AWS SSO CLI.

Flags:

 * `--diff` -- Print a diff of changes to the config file instead of modifying it
 * `--open` -- Specify how to open URls: [clip|exec|open]
 * `--print` -- Print profile entries instead of modifying config file
 * `--force` -- Write a new config file without prompting


By default, each profile is named according to the [ProfileFormat](
docs/config.md#profileformat) config option or overridden by the user defined
[Profile](docs/config.md#profile) option on a role by role basis.

For each profile generated, it will specify a [list of settings](
https://docs.aws.amazon.com/sdkref/latest/guide/settings-global.html) as defined
by the [ConfigVariables](docs/config.md#configvariables) setting in the
`~/.aws-sso/config.yaml`.

For more information on this feature, [read the Quickstart Guide](
docs/quickstart.md#integrating-with-the-aws-profile-variable).

Unlike with other ways to use AWS SSO CLI, the AWS IAM STS credentials will
_automatically refresh_.  This means, if you do not have a valid AWS SSO token,
you will be prompted to authentiate via your SSO provider and subsequent
requests to obtain new IAM STS credentials will automatically happen as needed.

**Note:** Due to a limitation in the AWS tooling, `print` and `printurl` are not
supported values for `--url-action`.  Hence, you must use `open` or `exec` to
auto-open URLs in your browser (recommended) or `clip` to automatically copy
URLs to your clipboard.  _No user prompting is possible._

**Note:** You should run this command any time your list of AWS roles changes
in order to update the `~/.aws/config` file or enable [AutoConfigCheck](
docs/config.md#AutoConfigCheck) and [ConfigUrlAction](
docs/config.md#ConfigUrlAction).

**Note:** If `ConfigUrlAction` is set, then `--open` is optional, otherwise it
is required.

**Note:** It is important that you do _NOT_ remove the `# BEGIN_AWS_SSO_CLI` and
`# END_AWS_SSO_CLI` lines from your config file!  These markers are used to track
which profiles are managed by AWS SSO CLI.

**Note:** This command does not honor the `--sso` option as it operates on all
of the configured AWS SSO instances in the `~/.aws-sso/config.yaml` file.

---

### eval

Generate a series of `export VARIABLE=VALUE` lines suitable for sourcing into your
shell.  Allows obtaining new AWS credentials without starting a new shell.  Can be
used to refresh existing AWS credentials or by specifying the appropriate arguments.

Suggested use (bash): `eval $(aws-sso eval <args>)`

Flags:

 * `--arn <arn>`, `-a` -- ARN of role to assume
 * `--account <account>`, `-A` -- AWS AccountID of role to assume (requires `--role`)
 * `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`)
 * `--profile <profile>`, `-p` -- Name of AWS Profile to assume
 * `--no-region` -- Do not set the AWS_DEFAULT_REGION from config.yaml
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
 * `--no-region` -- Do not set the AWS_DEFAULT_REGION from config.yaml

Arguments: `[<command>] [<args> ...]`

Priority is given to:

 * `--profile`
 * `--arn` (`$AWS_SSO_ROLE_ARN`)
 * `--account` (`$AWS_SSO_ACCOUNT_ID`) and `--role` (`$AWS_SSO_ROLE_NAME`)
 * Prompt user interactively

You can not run `exec` inside of another `exec` shell.

See [Environment Variables](#environment-variables) for more information about what varibles are set.

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

Priority is given to:

 * `--profile`
 * `--arn`
 * `--account` and `--role`

**Note:** The `process` command does not honor the `$AWS_SSO_ROLE_ARN`, `$AWS_SSO_ACCOUNT_ID`, or
`$AWS_SSO_ROLE_NAME` environment variables.

**Note:** Due to a limitation of the AWS tooling, setting `--url-action print` will cause an error
because of a limitation of the AWS tooling which prevents it from working.

---

### cache

AWS SSO CLI caches information about your AWS Accounts, Roles and Tags for better
perfomance.  By default it will refresh this information after 24 hours, but you
can force this data to be refreshed immediately.

Cache data is also automatically updated anytime the `config.yaml` file is modified.

---

### list

List will list all of the AWS Roles you can assume with the metadata/tags available
to be used for interactive selection with `exec`.  You can control which fields are
printed by specifying the field names as arguments.

Flags:

 * `--list-fields`, `-f` -- List the available fields to print

Arguments: `[<field> ...]`

The arguments are a list of fields to display in the report.  Overrides the
defaults and/or the specified `ListFields` in the `config.yaml`.

Default fields:

 * `AccountId`
 * `AccountAlias`
 * `RoleName`
 * `ExpiresStr`

---

### flush

Flush any cached AWS SSO/STS credentials.  By default, it only flushes the
temporary STS IAM role credentials for the selected SSO instance.

Flags:

 * `--type`, `-t` -- Type of credentials to flush:
    * `sts` -- Flush temporary STS credentials for IAM roles
    * `sso` -- Flush temporary AWS SSO credentials
	* `all` -- Flush temporary STS and SSO  credentials

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

---

### install-completions

Configures your appropriate shell configuration file to add auto-complete
functionality for commands, flags and options.  Must restart your shell
for this to take effect.

Modifies the following file based on your shell:
 * `~/.bash_profile` -- bash
 * `~/.zshrc` -- zsh

## Environment Variables

### Honored Variables

The following environment variables are honored by `aws-sso`:

 * `AWS_SSO_FILE_PASSWORD` -- Password to use with the `file` SecureStore
 * `AWS_SSO_CONFIG` -- Specify an alternate path to the `aws-sso` config file
 * `AWS_SSO_BROWSER` -- Override default browser for AWS SSO login
 * `AWS_SSO` -- Override default AWS SSO instance to use
 * `AWS_SSO_ROLE_NAME` -- Used for `--role`/`-R` with some commands
 * `AWS_SSO_ACCOUNT_ID` -- Used for `--account`/`-A` with some commands
 * `AWS_SSO_ROLE_ARN` -- Used for `--arn`/`-a` with some commands and with `eval --refresh`

The `file` SecureStore will use the `AWS_SSO_FILE_PASSWORD` environment
variable for the password if it is set. (Not recommended.)

Additionally, `$AWS_PROFILE` is honored via the standard AWS tooling when using
the [config](#config) command to manage your `~/.aws/config` file.

---

### Managed Variables

The following [AWS environment variables](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
are automatically set by `aws-sso`:

 * `AWS_ACCESS_KEY_ID` -- Authentication identifier required by AWS
 * `AWS_SECRET_ACCESS_KEY` -- Authentication secret required by AWS
 * `AWS_SESSION_TOKEN` -- Authentication secret required by AWS
 * `AWS_DEFAULT_REGION` -- Region to use AWS with (will never override an existing value)

The following environment variables are specific to `aws-sso`:

 * `AWS_SSO_ACCOUNT_ID` -- The AccountID for your IAM role
 * `AWS_SSO_ROLE_NAME` -- The name of the IAM role
 * `AWS_SSO_ROLE_ARN` -- The full ARN of the IAM role
 * `AWS_SSO_SESSION_EXPIRATION`  -- The date and time when the IAM role credentials will expire
 * `AWS_SSO_DEFAULT_REGION` -- Tracking variable for `AWS_DEFAULT_REGION`
 * `AWS_SSO_PROFILE` -- User customizable varible using the [ProfileFormat](docs/config.md#profileformat) template
 * `AWS_SSO` -- AWS SSO instance name
