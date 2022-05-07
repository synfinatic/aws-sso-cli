# Configuration

By default, `aws-sso` stores it's configuration file in `~/.aws-sso/config.yaml`,
but this can be overridden by setting `$AWS_SSO_CONFIG` in your shell or via the
`--config` flag.

The first time you run `aws-sso` and it detects there is no configuration file,
it will prompt you for a number of questions to give you a basic configuration.
Afterwords, you can edit the file and adjust the settings as desired.

```yaml
SSOConfig:
    <Name of AWS SSO>:
        SSORegion: <AWS Region where AWS SSO is deployed>
        StartUrl: <URL for AWS SSO Portal>
        DefaultRegion: <AWS_DEFAULT_REGION>
        Accounts:  # optional block for specifying tags & overrides
            <AccountId>:
                Name: <Friendly Name of Account>
                DefaultRegion: <AWS_DEFAULT_REGION>
                Tags:  # tags for all roles in the account
                    <Key1>: <Value1>
                    <Key2>: <Value2>
                Roles:
                    <Role Name>:
                        Profile: <ProfileName>
                        DefaultRegion: <AWS_DEFAULT_REGION>
                        Tags:  # tags specific for this role (will override account level tags)
                            <Key1>: <Value1>
                            <Key2>: <Value2>
                        Via: <Previous Role>  # optional, for role chaining
                        SourceIdentity: <Source Identity>

# See description below for these options
DefaultRegion: <AWS_DEFAULT_REGION>
DefaultSSO: <name of AWS SSO>
CacheRefresh: <hours>

Browser: <path to web browser>
UrlAction: [clip|exec|print|printurl|open]
UrlExecCommand:
    - <command>
    - <arg 1>
    - <arg N>
    - "%s"
FirefoxOpenInContainer: [False|True]
AutoConfigCheck: [False|True]
ConfigProfilesUrlAction: [clip|exec|open]

ConsoleDuration: <minutes>

LogLevel: [error|warn|info|debug|trace]
LogLines: [true|false]
HistoryLimit: <integer>
HistoryMinutes: <integer>

SecureStore: [file|keychain|kwallet|pass|secret-service|wincred|json]
JsonStore: <path to json file>

ProfileFormat: "<template>"
ConfigVariables:
    <Var1>: <Value1>
    <Var2>: <Value2>
    <VarN>: <ValueN>

AccountPrimaryTag:
    - <tag 1>
    - <tag 2>
    - <tag N>
PromptColors:
    <Option 1>: <Color>
    <Option 2>: <Color>
    <Option N>: <Color>
ListFields:
    - <field 1>
    - <field 2>
    - <field N>
EnvVarTags:
    - <Tag1>
    - <Tag2>
    - <TagN>
```

## SSOConfig

This is the top level block for your AWS SSO instances.  Typically an
organization will have a single AWS SSO instance for all of their accounts
under a single AWS master payer account.  If you have more than one AWS SSO
instance, then `Default` will be the default unless overridden with
`DefaultSSO`.

The `SSOConfig` config block is required.

### StartUrl

Each AWS SSO instance start URL hosted by AWS for interacting with your
SSO provider (Okta/OneLogin/etc).  Should be in the format of
`https://xxxxxxx.awsapps.com/start`.

**Note:** If you need to authenticate as different users to the same
AWS SSO Instance, you can specify multiple [SSOConfig](#ssoconfig) blocks
with the same `StartUrl`.

The `StartUrl` is required.

### SSORegion

Each AWS SSO instance is configured in a specific AWS region which needs to be
set here.

The `SSORegion` is required.

### DefaultRegion

The `DefaultRegion` allows you to define a value for the `$AWS_DEFAULT_REGION`
when switching to a role.  Note that, aws-sso will NEVER change an existing
`$AWS_DEFAULT_REGION` set by the user.

`DefaultRegion` can be specified at the following levels and the first match is
selected (most specific to most generic):

 1. At the inidividual role level: `SSOConfig -> <AWS SSO Instance> -> Accounts -> <AccountId> -> Roles -> <RoleName>`
 1. At the AWS Account level:`SSOConfig -> <Name of the AWS SSO> -> Accounts -> <AccountId>`
 1. At the AWS SSO Instance level: `SSOConfig -> <AWS SSO Instance>`
 1. At the config file level (default is `us-east-1`)

### Accounts

The `Accounts` block is completely optional!  The only purpose of this block
is to allow you to add additional tags (key/value pairs) to your accounts/roles
to make them easier to select.

#### Name

Alternate name of the account.  Shown as `AccountName` for the list command.
Not to be confused with the `AccountAlias` which is defined by the account owner
in AWS.

#### Tags

List of key / value pairs, used by `aws-sso` in prompt mode.  Any tag placed at
the account level will be applied to all roles in that account.

Some special tags:

 * **Color** -- Used to specify the color of the [Firefox container](#firefoxopenurlincontainer) label.  Valid values are:
	* blue
	* turquoise
	* green
	* yellow
	* orange
	* red
	* pink
	* purple
 * **Icon** -- Used to specify the icon of the [Firefox container](#firefoxopenurlincontainer) label.  Valid values are:
	* fingerprint
	* briefcase
	* dollar
	* cart
	* gift
	* vacation
	* food
	* fruit
	* pet
	* tree
	* chill
	* circle

#### Roles

The `Roles` block is optional, except for roles you which to assume via role chaining.

##### Profile

Define a custom `$AWS_PROFILE` / `$AWS_SSO_PROFILE` value for this role which overrides
the [ProfileFormat](#profileformat) config option.

Roles, just like [Accounts](#accounts) also accept [Tags](#tags) which are
specific to that role and override any account level tags.

##### Via

Impliments the concept of [role chaining](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html).

`Via` defines which role to assume before calling [sts:AssumeRole](
https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) in
order to switch to the specified role.  This allows you to define and assume
roles in AWS accounts that are not included in your organization's AWS SSO
scope or roles that were not defined via an [AWS SSO Permission Set](
https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html).

##### SourceIdentity

An [optional string](
https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters)
which must not start with `aws:` that your administrator may require you to set
in order to assume a role with `Via`.

## DefaultSSO

If you only have a single AWS SSO instance, then it doesn't really matter what
you call it, but if you have two or more, than `Default` is automatically
selected unless you manually specify it here, on the CLI (`--sso`), or via
the `AWS_SSO` environment variable.

## CacheRefresh

This is the number of hours between automatically refreshing your AWS SSO cache
to detect any changes in the roles you have been granted access to.  The default
is 24 (1 day).  Disable this feature by setting to any value <= 0.

**Note:** If this feature is disabled, then [AutoConfigCheck](#autoconfigcheck)
is also disabled.

## Browser / UrlAction / UrlExecCommand


`UrlAction` gives you control over how AWS SSO and AWS Console URLs are opened
in a browser:

 * `clip` -- Copies the URL to your clipboard
 * `exec` -- Execute the command provided in `UrlExecCommand`
 * `open` -- Opens the URL in your default browser or the browser you specified
    via `--browser` or `Browser`
 * `print` -- Prints the URL with a message in your terminal to stderr
 * `printurl` -- Prints only the URL in your terminal to stderr

If `Browser` is not set, then your default browser will be used and that
your browser needs to support JavaScript for the AWS SSO user interface.

`UrlExecCommand` is used with `UrlAction: exec` and allows you to execute
arbitrary commands to handle the URL.  The command and arguments should be
specified as a list, with the URL to open specified as the format string `%s`.
Only one instance of `%s` is allowed.  Note that YAML requires quotes around
strings which start with a [reserved indicator](
https://yaml.org/spec/1.2-old/spec.html#id2774228) like `%`.

Examples:

```yaml
# Open the AWS Console in your default browser
UrlAction: open
```

```yaml
# Open the AWS Console using Brave on MacOS
UrlAction: exec
UrlExecCommand:
    - open
    - -a
    - /Applications/Brave Browser.app
    - --args
    - "%s"
```

## FirefoxOpenUrlInContainer

`FirefoxOpenUrlInContainer` is used with `UrlAction: exec` and [Firefox](
https://getfirefox.com) with the [Firefox Open URL in Container](
https://addons.mozilla.org/en-US/firefox/addon/open-url-in-container/) v1.0.3
plugin.  This causes the generated URL to be of the format:

```
ext+container:name=<ProfileName>&url=<AWS Console URL>
```

The result is that each account/role has a dedicated Firefox container named
after the _ProfileName_ so that you can be logged in across multiple AWS
accounts/roles without getting an error from AWS.

Example:

```yaml
# Open the AWS Console in a Firefox container on MacOS
UrlAction: exec
UrlExecCommand:
    - /Applications/Firefox.app/Contents/MacOS/firefox
    - "%s"
FirefoxOpenUrlInContainer: True
```

**Note:** If your `ProfileFormat` generates a _ProfileName_ with an `&`, then
`{{ .AccountId }}:{{ .RoleName }}` will be used as the container name instead.

**Note:** You can control the color and icon of the container label using
[Tags](#tags).

**Note for MacOS users:** This feature does not work with the bundle directory,
so you should specify `/Applications/Firefox.app/Contents/MacOS/firefox` (
or as appropriate) as the command to execute.

You can disable this feature on the command line via the `--no-config-check`
flag.  `ConfigProfilesUrlAction` is also the default action when manually
running `aws-sso config-profiles`.

## ConfigProfilesUrlAction

This sets your default `--url-action` in your `~/.aws/config` when generating
named AWS profiles for use with `$AWS_PROFILE` and the default value for the
[config-profiles]

Due to limitations with the AWS SDK, only the following options are valid:

 * `clip`
 * `exec`
 * `open`

**Note:** This option is required if you also want to use [AutoConfigCheck](
#autoconfigcheck).

**Note:** This config option was previously known as `ConfigUrlAction` which
has been deprecated.

## AutoConfigCheck

When set to `True`, when you AWS SSO roles are automatically refreshed (see
[CacheRefresh](#cacherefresh)) `aws-sso` will also check to see if any changes
are warranted in your `~/.aws/config`.

**Note:** This option requires you to also set [ConfigProfilesUrlAction](
#configprofilesaction).

This option can be disabled temporarily on the command line by passing
the `--no-config-check` flag.

## LogLevel / LogLines

By default, the `LogLevel` is 'warn'.  You can override it here or via
`--log-level` with one of the following values:

 * `error`
 * `warn`
 * `info`
 * `debug`
 * `trace`

`LogLines` includes the file name/line and module name with each log for
advanced debugging.

## ConsoleDuration

Number of minutes an AWS Console session is valid for (default 60).  If you wish
to override the default session duration, you can specify the number of minutes
here or with the `--duration` flag.

[Per AWS](
https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)
this value must be betwen 15 and 2160 (36 hours) because `ConsoleDuration`
is in minutes and not seconds.

## SecureStore / JsonStore

`SecureStore` supports the following backends:

 * `file` - Encrypted local files (OS agnostic and default on Linux)
 * `keychain` - macOS [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac) (default on macOS)
 * `kwallet` - [KDE Wallet](https://utils.kde.org/projects/kwalletmanager/)
 * `pass` - [pass](https://www.passwordstore.org)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0) (default on Windows)
 * `json` - Cleartext JSON file (very insecure and not recommended).  Location
    can be overridden with `JsonStore`

## ProfileFormat

AWS SSO CLI can set an environment variable named `AWS_SSO_PROFILE` with
any value you can express using a [Go Template](https://pkg.go.dev/text/template)
which can be useful for modifying your shell prompt and integrate with your own
tooling.

The following variables are accessible from the `AWSRoleFlat` struct:

 * `Id` -- Unique integer defined by AWS SSO CLI for this role
 * `AccountId` -- AWS Account ID (int64)
 * `AccountAlias` -- AWS Account Alias defined in AWS
 * `AccountName` -- AWS Account Name defined in AWS or overridden in AWS SSO's config
 * `EmailAddress` -- Root account email address associated with the account in AWS
 * `Expires` -- When your API credentials expire (string)
 * `Arn` -- AWS ARN for this role
 * `RoleName` -- The role name
 * `DefaultRegion` -- The manually configured default region for this role
 * `SSO` -- Name of the AWS SSO instance
 * `SSORegion` -- The AWS Region where AWS SSO is enabled in your account
 * `StartUrl` -- The AWS SSO start URL for your account
 * `Tags` -- Map of additional custom key/value pairs
 * `Via` -- Role AWS SSO CLI will assume before assuming this role

By default, `ProfileFormat` is set to `{{ AccountIdStr .AccountId }}:{{ .RoleName }}`.

AWS SSO CLI uses [sprig](http://masterminds.github.io/sprig/) for most of its
functions, but a few custom functions are available:

 * `AccountIdStr(x)` -- Converts an AWS Account ID to a string
 * `EmptyString(x)` -- Returns true/false if the value `x` is an empty string
 * `FirstItem([]x)` -- Returns the first item in a list that is not an empty string
 * `StringsJoin(x, []y)` -- Joins the items in `y` with the string `x`

**Note:** Unlike most values stored in the `config.yaml`,  you will need to
single-quote (`'`) the value because because `ProfileFormat` values often start
with a `{`.

For more information, [see the FAQ](FAQ.md#how-to-configure-profileformat).

## ConfigVariables

Define a set of [config settings](
https://docs.aws.amazon.com/sdkref/latest/guide/settings-global.html) for each 
profile in your `~/.aws/config` file generated via the [config-profiles](
commands.md#config-profiles) command.

Some examples to consider:

 * `sts_regional_endpoints: regional`
 * `output: json`

## AccountPrimaryTag

When selecting a role, if you first select by role name (via the `Role` tag) you
will be presented with a list of matching ARNs to select. The
`AccountPrimaryTag` automatically includes another tag name and value as the
description to aid in role selection.  By default the following tags are
searched (first match is used):

 * `AccountName`
 * `AccountAlias`
 * `Email`

Set `AccountPrimaryTag` to an empty list to disable this feature.

## PromptColors

`PromptColors` takes a map of prompt options and color options allowing you to
have complete control of how AWS SSO CLI looks.  You only need to specify the
options you wish to override, but do not include the `PromptColors` if you have
no options.  More information about the meaning and use of the options below,
[refer to the go-prompt docs](
https://pkg.go.dev/github.com/c-bata/go-prompt#Option).

Valid options:

 * `DescriptionBGColor`
 * `DescriptionTextColor`
 * `InputBGColor`
 * `InputTextColor`
 * `PrefixBackgroundColor`
 * `PrefixTextColor`
 * `PreviewSuggestionBGColor`
 * `PreviewSuggestionTextColor`
 * `ScrollbarBGColor`
 * `ScrollbarThumbColor`
 * `SelectedDescriptionBGColor`
 * `SelectedDescriptionTextColor`
 * `SelectedSuggestionBGColor`
 * `SelectedSuggestionTextColor`
 * `SuggestionBGColor`
 * `SuggestionTextColor`

Valid low intensity colors:

 * `Black`
 * `DarkRed`
 * `DarkGreen`
 * `Brown`
 * `DarkBlue`
 * `Purple`
 * `Cyan`
 * `LightGrey`

Valid high intensity colors:

 * `DarkGrey`
 * `Red`
 * `Green`
 * `Yellow`
 * `Blue`
 * `Fuchsia`
 * `Turquoise`
 * `White`

## HistoryLimit

Limits the number of recently used roles tracked via the History tag.
Default is last 10 unique roles.  Set to 0 to disable.

## HistoryMinutes

Limits the list of recently used roles tracked via the History tag to
roles that were last used within the last X minutes.  Set to 0 to not limit
based on the time.  Default is 1440 minutes (24 hours).

This option has no effect if `HistoryLimit` is set to 0.

## ListFields

Specify which fields to display via the `list` command.  Valid options are:

 * `Id` -- Unique row identifier
 * `AccountAlias` -- Account Name from AWS SSO
 * `AccountId` -- AWS Account Id
 * `AccountName` -- Account Name from config.yaml
 * `Arn` -- Role ARN
 * `DefaultRegion` -- Configured default region
 * `EmailAddress` -- Email address of root account associated with AWS Account
 * `Expires` -- Unix epoch time when cached STS creds expire
 * `ExpiresStr` -- Hours and minutes until cached STS creds expire
 * `Profile` -- Value used for `$AWS_SSO_PROFILE` and the profile name in `~/.aws/config`
 * `RoleName` -- Role name
 * `SSO` -- AWS SSO instance name
 * `Via` -- Role Chain Via

## EnvVarTags

List of tag keys that should be set as a shell environment variable when
using the `eval` or `exec` commands.

**Note:** These environment variables are considered completely owned and
controlled by `aws-sso` so any existing value will be overwritten.

**Note:** This feature is not compatible when using roles using the
`$AWS_PROFILE` via the `config` command.
