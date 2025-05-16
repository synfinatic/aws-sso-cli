# Configuration

By default, `aws-sso` will by default store all it's configuration and state files in
`~/.config/aws-sso` for versions `>= 1.17.0` per the [XDG spec](
https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html).  
Previous versions of `aws-sso` used `~/.aws-sso`.  Users at their own descresion may move the
files to the new location.  To keep files co-located in the same place, if the directory
`~/.aws-sso` exists, then it will be used.

**Note:** The `aws-sso` documentation will generally use the older file path (`~/.aws-sso/...`)
when describing file locations.

The main configuration file is named `~/.aws-sso/config.yaml`, but this can be overridden by
setting `$AWS_SSO_CONFIG` in your shell or via the `--config` flag.

The first time you run `aws-sso` and it detects there is no configuration file,
it will prompt you for a number of questions to give you a basic configuration.
Afterwords, you can edit the file and adjust the settings as desired or run
[aws-sso setup wizard](commands.md#setup-wizard).

```yaml
SSOConfig:
    <Name of AWS SSO>:
        SSORegion: <AWS Region where AWS SSO is deployed>
        StartUrl: <URL for AWS SSO Portal>
        DefaultRegion: <AWS_DEFAULT_REGION>
        AuthUrlAction: [clip|exec|print|printurl|open|granted-containers|open-url-in-container]
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
AutoConfigCheck: [false|true]
AutoLogin: [false|true]
Threads: <integer>
MaxRetry: <integer>
MaxBackoff: <integer>

Browser: <path to web browser>
UrlAction: [clip|exec|print|printurl|open|granted-containers|open-url-in-container]
ConfigProfilesBinaryPath: <path to aws-sso binary>
UrlExecCommand:
    - <command>
    - <arg 1>
    - <arg N>
    - "%s"
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

FirstTag: <Tag Name>
FullTextSearch: [true|false]
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
in AWS.  For more information, [read the FAQ](FAQ.md#accountname-vs-accountalias)

#### Tags

List of key / value pairs, used by `aws-sso` in prompt mode.  Any tag placed at
the account level will be applied to all roles in that account.

Some special tags:

 * **Color** -- Used to specify the color of the [Firefox container](#authurlaction--browser--urlaction--urlexeccommand) label.  Valid values are:
   * blue
   * turquoise
   * green
   * yellow
   * orange
   * red
   * pink
   * purple
 * **Icon** -- Used to specify the icon of the [Firefox container](#authurlaction--browser--urlaction--urlexeccommand) label.  Valid values are:
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

Implements the concept of [role chaining](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html).

`Via` defines which role to assume before calling [sts:AssumeRole](
https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) in
order to switch to the specified role.  This allows you to define and assume
roles in AWS accounts that are not included in your organization's AWS SSO
scope or roles that were not defined via an [AWS SSO Permission Set](
https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html).

The value of the `Via` must be that of an ARN.  If the initial role is a role managed
via AWS Identity Center, use the standard IAM Role ARN format of: `arn:aws:iam::<acccountid>:role/<rolename>`
and NOT the actual IAM Role that Identity Center creates which is of the format:
`arn:aws:iam::<accountid>:/role/aws-reserved/sso.amazonaws.com/<sso-region>/AWSReservedSSO_<rolename>_<random>`

Note: `aws-sso` does not manage, create or configure the necessasry IAM permissions on
either role to grant permissions to successfully perform the `sts:AssumeRole` action.
For this functionality to work, you must configure the IAM permissions to allow this
operation to be successful.

Example:

```yaml
SSOConfig:
  Default:
    Accounts:
      072668187369:
        Roles:
          AssumeRoleAdmin:
            Via: "arn:aws:iam::647310151462:role/sandbox-05-assumeroleadmin"
```

Will allow a user to assume the non-AWS Identity Center role
`aws:iam::072668187369:roles/AssumeRoleAdmin` via the AWS Identity Center managed
role `arn:aws:iam::647310151462:role/sandbox-05-assumeroleadmin`.

Note: The [aws-sso console](https://github.com/synfinatic/aws-sso-cli/issues/1205) command
is not supported for roles accessed using the `Via` feature.

##### SourceIdentity

An [optional string](
https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters)
which must not start with `aws:` that your administrator may require you to set
in order to assume a role with `Via`.

## Common Config Options

### DefaultSSO

If you only have a single AWS SSO instance, then it doesn't really matter what
you call it, but if you have two or more, than `Default` is automatically
selected unless you manually specify it here, on the CLI (`--sso`), or via
the `AWS_SSO` environment variable.

### SSO Cache Options

#### CacheRefresh

This is the number of hours between automatically refreshing your AWS SSO cache
to detect any changes in the roles you have been granted access to.  The default
is 168 (7 days).  Disable this feature by setting to any value <= 0.

**Note:** If this feature is disabled, then [AutoConfigCheck](#autoconfigcheck)
is also disabled.

#### Threads

Certain actions when communicating with AWS can be accellerated by running multiple
parallel threads.  Must be >= 1.  Default is 5 threads.  Note that too many threads
can actually hurt performance for large number of accounts!

#### MaxRetry

Maximum number of attempts before aborting.  Default is 10 which seems optimal
for <= 50 accounts.  Value must be > 0.

#### MaxBackoff

Maximum number of seconds to wait before retrying.  Too low of a
value will cause retries to fail more often.  Too high of a value will hurt
performance.  Default is 5 seconds which seems optional for <= 50 accounts.
Value must be > 0.

### Browser Integration

#### AuthUrlAction / Browser / UrlAction / UrlExecCommand

`UrlAction` gives you control over how AWS SSO and AWS Console URLs are opened
in a browser:

 * `clip` -- Copies the URL to your clipboard
 * `exec` -- Execute the command provided in `UrlExecCommand`
 * `granted-containers`  -- Generates a URL for the Firefox
    [Granted Containers](https://addons.mozilla.org/en-US/firefox/addon/granted/) plugin and
    runs your `UrlExecCommand`
 * `open` -- Opens the URL in your default browser or the browser you specified
    via `--browser` or `Browser`
 * `open-url-in-container` -- Generates a URL for the Firefox [Open Url in Container](
    https://addons.mozilla.org/en-US/firefox/addon/open-url-in-container/)
    plugin and runs your `UrlExecCommand`.
 * `print` -- Prints the URL with a message in your terminal to stderr
 * `printurl` -- Prints only the URL in your terminal to stderr

If `Browser` is not set, then your default browser will be used and that
browser needs to support JavaScript for the AWS SSO user interface.

`UrlExecCommand` is used with `UrlAction: exec` and the two Firefox containers
plugin options (`granted-containers` / `open-url-in-container`) and allows you
to execute arbitrary commands to handle the URL.  The command and arguments should be
specified as a list, with the URL to open specified as the format string `%s`.
Only one instance of `%s` is allowed.  Note that YAML requires quotes around
strings which start with a [reserved indicator](
https://yaml.org/spec/1.2-old/spec.html#id2774228) like `%`.

`AuthUrlAction` allows you to override the global `UrlAction` when authenticating
with your SSO provider to retrieve an AWS SSO token.

Examples:

##### Open URL In Default Browser

```yaml
UrlAction: open
```

##### Open URL In Non-Default Browser

```yaml
UrlAction: exec
UrlExecCommand:
    - open
    - -a
    - /Applications/Brave Browser.app
    - --args
    - "%s"
```

##### Open URL in Firefox Container

Opens each IAM Role (and SSO Login page) in a unique Firefox Container using the
[Open Url in Container](
https://addons.mozilla.org/en-US/firefox/addon/open-url-in-container/)
Firefox plugin.

```yaml
UrlAction: open-url-in-container
UrlExecCommand:
    - /Applications/Firefox.app/Contents/MacOS/firefox
    - "%s"
```

**Note:** If you do not want your SSO Login page to be opened in a container,
use the [AuthUrlAction](#authurlaction--browser--urlaction--urlexeccommand)
option to specify a different action:

```yaml
SSOConfig:
    Default:
        SSORegion: us-east-1
        StartUrl: https://example.awsapps.com/start
        AuthUrlAction: open
UrlAction: open-url-in-container
UrlExecCommand:
    - /Applications/Firefox.app/Contents/MacOS/firefox
    - "%s"
```

##### Use custom shell script

```yaml
UrlAction: exec
UrlExecCommand:
    - ~/bin/open_url.sh
    - "%s"
```

**Note:** If your `ProfileFormat` generates a _ProfileName_ with an `&`, then
`{{ .AccountId }}:{{ .RoleName }}` will be used as the Firefox container name instead.

**Note:** You can control the color and icon of the Firefox container label using
[Tags](#tags).

**Note for MacOS users:** This feature does not work with the bundle directory,
so you should specify `/Applications/Firefox.app/Contents/MacOS/firefox` (or as
appropriate) as the command to execute.

#### ConsoleDuration

Number of minutes an AWS Console session is valid for (default 60).  If you wish
to override the default session duration, you can specify the number of minutes
here or with the `--duration` flag.

Note that even though [AWS documents](
https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)
the API call to get a Console URL to be between 15 minutes and 36 hours, the
real limit is 12 hours (720 minutes) because AWS SSO sessions [are limited to
12 hours maximum](
https://docs.aws.amazon.com/singlesignon/latest/userguide/howtosessionduration.html).

### AWS_PROFILE Integration

#### ConfigProfilesBinaryPath

Override execution path for `aws-sso` when generating named AWS profiles via the
[config-profiles](commands.md#config-profiles).

#### ProfileFormat

AWS SSO CLI can set an environment variable named `AWS_SSO_PROFILE` with
any value you can express using a [Go Template](https://pkg.go.dev/text/template)
which can be useful for modifying your shell prompt and integrate with your own
tooling.

The following variables are accessible from the `AWSRoleFlat` struct:

 * `Id` -- Unique integer defined by AWS SSO CLI for this role
 * `AccountId` -- AWS Account ID (int64! not zero padded)
 * `AccountIdPad` -- AWS Account ID (zero padded)
 * `AccountAlias` -- [AWS Account Name](FAQ.md#accountname-vs-accountalias) defined in AWS by the account owner
 * `AccountName` -- AWS Account Name defined in `~/.aws-sso/config.yaml`
 * `EmailAddress` -- Root account email address associated with the account in AWS
 * `ExpiresEpoch` -- When your API credentials expire (UNIX epoch)
 * `Expires` -- When your API credentials expire (string)
 * `Arn` -- AWS ARN for this role
 * `RoleName` -- The role name
 * `DefaultRegion` -- The manually configured default region for this role
 * `SSO` -- Name of the AWS SSO instance
 * `SSORegion` -- The AWS Region where AWS SSO is enabled in your account
 * `StartUrl` -- The AWS SSO start URL for your account
 * `Tags` -- Map of additional custom key/value pairs
 * `Via` -- Role AWS SSO CLI will assume before assuming this role

By default, `ProfileFormat` is set to `{{ .AccountIdPad }}:{{ .RoleName }}`.

AWS SSO CLI uses [sprig](http://masterminds.github.io/sprig/) for most of its
functions, but a few custom functions are available:

 * `AccountIdStr(x)` -- Converts the `.AccountId` variable to a string.  Deprecated.  Use `.AccountIdPad` variable instead.
 * `EmptyString(x)` -- Returns true/false if the value `x` is an empty string
 * `FirstItem([]x)` -- Returns the first item in a list that is not an empty string
 * `StringsJoin(x, []y)` -- Joins the items in `y` with the string `x`

**Note:** Unlike most values stored in the `config.yaml`,  you will need to
single-quote (`'`) the value because because `ProfileFormat` values often start
with a `{`.

For more information, [see the FAQ](FAQ.md#profiles-and-tags).

#### ConfigVariables

Define a set of [config settings](
https://docs.aws.amazon.com/sdkref/latest/guide/settings-global.html) for each
profile in your `~/.aws/config` file generated via the [config-profiles](
commands.md#config-profiles) command.

Some examples to consider:

 * `sts_regional_endpoints: regional`
 * `output: json`

### Interactive Role Selection

#### FirstTag

When selecting a role, the tag key name at the top of the list will be this value regardless
of sort order.  Useful if you want `History` or some other tag easily accessible via arrow keys.

#### FullTextSearch

When set to `true`, searching via interactive exec mode (`aws-sso exec` without role selector args)
will cause searching to be done via substrings rather than the default prefix based search.

#### AccountPrimaryTag

When selecting a role, if you first select by role name (via the `Role` tag) you
will be presented with a list of matching ARNs to select. The
`AccountPrimaryTag` automatically includes another tag name and value as the
description to aid in role selection.  By default the following tags are
searched (first match is used):

 * `AccountName`
 * `AccountAlias`
 * `Email`

Set `AccountPrimaryTag` to an empty list to disable this feature.

#### PromptColors

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

#### HistoryLimit

Limits the number of recently used roles tracked via the History tag.
Default is last 10 unique roles.  Set to 0 to disable.

#### HistoryMinutes

Limits the list of recently used roles tracked via the History tag to
roles that were last used within the last X minutes.  Set to 0 to not limit
based on the time.  Default is 1440 minutes (24 hours).

This option has no effect if `HistoryLimit` is set to 0.

### Advanced Configuration Options

#### ListFields

Specify which fields to display via the `list` command.  Valid options are:

 * `Id` -- Unique row identifier
 * `AccountAlias` -- [Account Name in AWS](FAQ.md#accountname-vs-accountalias) as defined by the account owner
 * `AccountId` -- AWS Account Id
 * `AccountIdPad` -- AWS Account Id with leading zeros if necessary
 * `AccountName` -- Account Name from config.yaml
 * `Arn` -- Role ARN
 * `DefaultRegion` -- Configured default region
 * `EmailAddress` -- Email address of root account associated with AWS Account
 * `ExpiresEpoch` -- Unix epoch time when cached STS creds expire
 * `Expires` -- Hours and minutes until cached STS creds expire
 * `Profile` -- Value used for `$AWS_SSO_PROFILE` and the profile name in `~/.aws/config`
 * `RoleName` -- Role name
 * `SSO` -- AWS SSO instance name
 * `Via` -- Role Chain Via

#### AutoConfigCheck

When set to `true`, when your AWS SSO roles are automatically refreshed (see
[CacheRefresh](#cacherefresh)) `aws-sso` will also check to see if any changes
are warranted in your `~/.aws/config`.

**Note:** This option can be disabled temporarily on the command line by passing
the `--no-config-check` flag.

**Note:** If you are using a non-default path for your `~/.aws/config` file, then
you must be sure to set the `AWS_CONFIG_FILE` environment variable to the correct
path or disable this configuration option.

#### AutoLogin

When set to `true`, `aws-sso` will behave mostly like v1.x and automatically attempt to
login with your SSO provider to AWS Identity Center when your session has expired.
When set to `false` (the default) you must first run [aws-sso login](commands.md#login).

**Note:** This feature exists soley beacuse people don't like change.  Enabling this
really isn't ideal from a security standpoint since it makes it more likely that
an attempted phish attack will be successful.  Users should expect the login page to load
in their browser if and only if they have manually initiated the login process.

**Note:** that v2.x does not support the common [--no-config-check](
https://synfinatic.github.io/aws-sso-cli/v1.17.0/commands/#common-flags) flag that was
present in 1.x.

#### LogLevel / LogLines

By default, the `LogLevel` is 'info'.  You can override it here or via
`--log-level` with one of the following values:

 * `error`
 * `warn`
 * `info`
 * `debug`
 * `trace`

`LogLines` includes the file name/line and module name with each log for
advanced debugging.

#### SecureStore / JsonStore

`SecureStore` supports the following backends:

 * `file` - Encrypted local files (OS agnostic and default on Linux)
 * `keychain` - macOS [Keychain](https://support.apple.com/guide/mac-help/use-keychains-to-store-passwords-mchlf375f392/mac) (default on macOS)
 * `kwallet` - [KDE Wallet](https://github.com/KDE/kwalletmanager)
 * `pass` - [pass](https://www.passwordstore.org) (uses GPG on backend)
 * `secret-service` - Freedesktop.org [Secret Service](https://specifications.freedesktop.org/secret-service/latest/re01.html)
 * `wincred` - Windows [Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0) (default on Windows)
 * `json` - Cleartext JSON file (very insecure and not recommended).  Location
    can be overridden with `JsonStore`

**Note:** The `file` option supports passing in the password via the `AWS_SSO_FILE_PASSWORD` environment variable.

**Note:** The `pass` option supports passing in the password via the [gpg-agent](https://www.gnupg.org/documentation/manuals/gnupg24/gpg-agent.1.html).

#### EnvVarTags

List of tag keys that should be set as a shell environment variable when
using the `eval` or `exec` commands.

**Note:** These environment variables are considered completely owned and
controlled by `aws-sso` so any existing value will be overwritten.

**Note:** This feature is not compatible when using roles using the
`$AWS_PROFILE` via the `config` command.
