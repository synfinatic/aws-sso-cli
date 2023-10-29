# Frequently Asked Questions

## General Usage

### When will my credentials expire?

Your credentials will expire based on how long your administrator allows. To
see how long your credentials have until they expire, see the [list command](commands.md#list).

### Why can't aws-sso find my new role?

Most likely, this is because the aws-sso cache is out of
date.  You can force a refresh of the cache by running [aws-sso cache](commands.md#cache).

Note, if you have just been assigned a new PermissionSet in IAM Identity Center, it
tends to show up in the IAM Identity Center web console
(https://xxxxx.awsapps.com/start) before it is made available to `aws-sso` via the
[ListAccountRoles](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_ListAccountRoles.html)
API call.  Unfortunately, this seems to be a limitation with AWS and you just
have to wait a few minutes.

You can see what the AWS ListAccountRoles API is returning via `aws-sso cache -L debug`

--

## Advanced Features

### Does AWS SSO CLI support role chaining?

Yes.  You can use `aws-sso` to assume roles in other AWS accounts or
roles that are not managed via AWS SSO Permission Sets using [role chaining](
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html).

For more information on this, see the [Via](config.md#Via) configuration option.

You can also use the standard [aws config definition](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-role-overview):

```ini
[profile RoleToAssumeViaRoleChaining]
role_arn = arn:aws:iam::2373474565:role/SomeRoleToAsssume
source_profile = NameOfAwsSsoCliProfile
```

And generate the necessary AWS SSO CLI profile entries via
[aws-sso config-profiles](commands.md#config-profiles) command.

### How does AWS SSO CLI manage the $AWS\_DEFAULT\_REGION?

AWS SSO will leave the `$AWS_DEFAULT_REGION` environment variable alone
unless the following are all true:

 * The `$AWS_DEFAULT_REGION` is not already defined in your shell
 * You have specified the region in the `config.yaml` via `DefaultRegion`
 * You have not set the `--no-region` flag on the CLI
 * If `$AWS_SSO_DEFAULT_REGION` is set, does it match `$AWS_DEFAULT_REGION?`

If the above are true, then AWS SSO will define both:

 * `$AWS_DEFAULT_REGION`
 * `$AWS_SSO_DEFAULT_REGION`

to the default region as defined by `config.yaml`.  If the user changes
roles and the two variables are set to the same region, then AWS SSO will
update the region.   If the user ever overrides the `$AWS_DEFAULT_REGION`
value or deletes the `$AWS_SSO_DEFAULT_REGION` then AWS SSO will no longer
manage the variable.

<!-- https://github.com/synfinatic/aws-sso-cli/issues/166 -->
![](https://user-images.githubusercontent.com/1075352/143502947-1465f68f-0ef5-4de7-a997-ea716facc637.png)

### Example of multiple AWS SSO instances

This is an example of how to configure two different AWS SSO instances:

```yaml
SSOConfig:
  Primary:
    SSORegion: us-east-2
    StartUrl: https://d-123455555.awsapps.com/start
  Testing:
      SSORegion: us-east-1
      StartUrl: https://d-906766e422.awsapps.com/start
DefaultSSO: Primary
```

With the above config, `Primary` is the default AWS SSO instance, but you can
select `Testing` via the `--sso` argument or `$AWS_SSO` environment variable.

### Using non-default AWS SSO instances with auto-complete

The handling of the auto-completion of the `-A`, `-R`, and `-a` flags happens
before processing of the command line arguments so you can not use the `--sso` / `-S`
flag to specify a non-default AWS SSO instance.  The result is it will always
present your [DefaultSSO](config.md#defaultsso) list of accounts and roles.

If you wish to use auto-complete with a different AWS SSO instance, you must
first set the `AWS_SSO` environment variable in your shell:

```bash
$ export AWS_SSO=OtherInstance
$ aws-sso console ...
```

Note, the following shorter version of specifying it as a single command does not work:

```bash
$ AWS_SSO=OtherInstance aws-sso console ...
```

### Firefox container color/icon doesn't change

If you have modified your `Color` or `Icon` tag for an Account/Role and the
label doesn't change in Firefox, you will need to delete the container
so that it can be re-created or manually change the color/icon in the
Firefox setings `about:preferences#containers`.

![Firefox Container Settings](
https://user-images.githubusercontent.com/1075352/166166400-beff4928-9831-4270-8133-18727d9ade68.png)

### Multiple AWS SSO Instances

If you are using multiple AWS SSO Instances (multiple [SSOConfig](
config.md#SSOCOnfig) blocks) then a few comments:

1. You _really_ want to use the Firefox Containers plugin described above.  You
    will have a horrible time without this because you need to have different
    browser sessions/cookies for each AWS SSO Instance.
1. Choosing your [DefaultSSO](config.md#DefaultSSO) is important because
    auto-complete almost always will pick the DefaultSSO.
1. To override the `DefaultSSO` with auto-complete, you can't use the `-S`
    or `--sso` flag because of a [limitation with how shell completion works](
    https://github.com/synfinatic/aws-sso-cli/issues/382).  Instead you must
    first `export AWS_SSO=<name>` and then run the command.

--

## Security

### How do I delete all secrets from the macOS keychain?

 1. Open `/Applications/Utilities/Keychain Access.app`
 2. Choose the `login` keychain
 3. Find the entry named `aws-sso-cli` and right click -> `Delete "aws-sso-cli"`

### Which SecureStore should I use?

The answer depends, but if you are running AWS SSO CLI on macOS then I
recommend to use the default `keychain`.  Windows users should use the default
`wincred` store.  Both utilize the secure storage provided by Apple/Microsoft
and generally provides good security and ease of use.

If you are running on Linux, then consider `kwallet`, `pass` and
`secret-service` depending on which ever password manager you use.

You can always fall back to `file` which is an encrypted file.  Every time you
run AWS SSO CLI and it needs to open the file for read/writing data it will
prompt you for your password.  This is probably the best option for Linux
jumphosts.  In these cases, I suggest using the `eval` or `exec` command to
load the resulting AWS API credentials into your shell so that you don't have
to keep typing in your password contantly.  Of course, you can also set the
`$AWS_SSO_FILE_PASSWORD` environment variable in your shell to avoid typing
it in, but please make sure you are aware of the security implications of
doing so.

Lastly, there is the `json` storage backend which is _not_ secure.  It literally
is a plain, clear text JSON file stored on disk and is no better than the
official AWS tooling.  It is included here only for debug and development
purposes only.

Is there another secure storage backend you would like to see AWS SSO CLI
support?  If so, please [open a feature request](
https://github.com/synfinatic/aws-sso-cli/issues/new?assignees=&labels=enhancement&template=feature_request.md)
and let me know!

### Does aws-sso support using AWS FIPS endpoints?

Yes!  Please set the following environment variable and `aws-sso` will automatically
select the appropriate AWS FIPS endpoints when communicating with AWS:

`AWS_USE_FIPS_ENDPOINT=true`

### Are macOS Keychain items synced?

No. If you are using the macOS keychain, none of the secrets stored by `aws-sso`
are synced via iCloud to your other Apple devices.

### How can I stop typing my password all the time?

Choosing a [SecureStore](config.md#securestore-jsonstore) is important from
a usability & security perspective.  The default options for MacOS and Windows
should generally be the best, but Linux users default to `file` for compatibility
sake.

Unfortunately, the `file` option requires you to enter your password pretty much
every time you use `aws-sso`.  For that reason, I recommend using the [pass](
https://www.passwordstore.org) option which uses GPG and optionally the `gpg-agent`
for caching of your GPG passphrase.  Please note that configuring pass, GPG
and the gpg-agent are outside of the scope of this documentation.

### I'm now getting a warning in macOS after upgrading aws-sso-cli?

As of v1.9.10, `aws-sso-cli` is now distributed as a bottle in homebrew and
these binaries are not signed and will generate a warning that the binary
has changed.

If you prefer the old way of building locally from source to avoid the warning
you should use `brew install -s aws-sso-cli` or `brew upgrade -s aws-sso-cli`.

--

## Profiles and Tags

### AccountAlias vs AccountName

Due to poor decisions on my part, this is ugly.  Sorry about that.  With that
said...

The `AccountAlias` is defined by the AWS account owner for the account
via the AWS Console.  However, this is _not_ the
[AWS Account Alias](https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html#AboutAccountAlias),
but rather the [AWS Account Name](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-root-user.html)
which is retrieved via the AWS sso:ListAccount API.

The `AccountName` is defined explicitly in the `~/.aws-sso/config.yaml` file like this:

```yaml
SSOConfig:
  Default:
    SSORegion: us-east-1
    StartUrl: https://d-23234235.awsapps.com/start
    Accounts:
      2347575757:
        Name: Production
```

or automatically via the [ProfileFormat config option](config.md#profileformat).

So when you specify `AccountAlias` in the [ProfileFormat](config.md#ProfileFormat)
or see it in the [list](commands.md#list) command, you're actually using the
AWS Account Name set by the account owner.

### Defining `$AWS_PROFILE` and `$AWS_SSO_PROFILE` variable names

As [covered here](index.md#environment-variables), AWS SSO CLI will set the
`$AWS_SSO_PROFILE` variable when you use [exec](index.md#exec) or [eval](
index.md#eval) and can honor the `$AWS_PROFILE` variable.

AWS SSO CLI tries to make it easy to manage many roles across many accounts
by giving users a lot of control over what the value of these variables are for
each role.

 * You can use [ProfileFormat](config.md#profileformat) to create an
    auto-generated profile name for each role based upon things like the
    AccountID, AccountName, RoleName, etc.
 * You can also use [Profile](config.md#profile) to define a profile name for
    any specific role.
 * You can also use both: `ProfileFormat` to set a default value and override
    specific roles that you use more often via `Profile` with an easier to
    remember value.  The choice is yours, but remember that every unique Role
    ARN needs a unique value if you wish to use it to select a role to use
    via `$AWS_PROFILE` and the [config-profiles](commands.md#config-profiles)
    command.

### How to configure ProfileFormat

`aws-sso` uses the `ProfileFormat` configuration option for two different
purposes:

 1. Makes it easy to modify your shell `$PROMPT` to include information
    about what AWS Account/Role you have currently assumed by defining the
    `$AWS_SSO_PROFILE` environment variable.
 2. Makes it easy to select a role via the `$AWS_PROFILE` environment variable
    when you use the [config-profiles](commands.md#config-profiles) command.

By default, `ProfileFormat` is set to `{{ .AccountIdPad }}:{{ .RoleName }}`
which will generate a value like `02345678901:MyRoleName`.  For a complete
list of available variable names, see [ProfileFormat](config.md#profileformat).

In my experience you can change the `ProfileFormat` to pretty much any valid
ASCII string that does not include whitespace or special characters that would
be evaluated by your shell (`$`, etc) or
[the AWS configuration file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-using-profiles)
such as `[`, `]`.  (Note: if you can find official AWS documentation on this
subject, please let me know!)

Some example `ProfileFormat` values:

 * `'{{ FirstItem .AccountName .AccountAlias }}'` -- If there
    is an Account Name set in the config.yaml print that, otherwise print the
    Account Name defined by the AWS account owner.
 * `'{{ .AccountIdPad }}'` -- Pad the AccountId with leading zeros if it is < 12 digits long
 * `'{{ .AccountId }}'` -- Print the AccountId as a regular number
 * `'{{ StringsJoin ":" .AccountAlias .RoleName }}'` -- Another
    way of writing `{{ .AccountAlias }}:{{ .RoleName }}`
 * `'{{ StringReplace " " "_" .AccountAlias }}'` -- Replace any spaces (` `) in the AccountAlias with an underscore (`_`).
 * `'{{ FirstItem .AccountName (nospace .AccountAlias) }}:{{ .RoleName }}'`
    -- Use the Account Name if set, otherwise use the Account Alias (without spaces via
    [nospace](http://masterminds.github.io/sprig/strings.html#nospace))
    and then append a colon, followed by the IAM Role Name.
 * `'{{ kebabcase .AccountAlias }}:{{ .RoleName }}'
	-- Reformat the AWS account alias like `AStringLikeThis` into
	`a-string-like-this` using the [kebabcase function](
	http://masterminds.github.io/sprig/strings.html#kebabcase).

For a full list of available variables and functions, see the
[ProfileFormat config option](config.md#profileformat).

To see a list of values across your roles for a given variable, you can use
the [list](index.md#list) command.

### Spaces are invalid in Profile names

If your [ProfileFormat](config.md#ProfileFormat) contains either `AccountName`
or `AccountAlias` you may end up with an invalid Profile name which contains a
space.

Their are two possible solutions:

 1. Don't include a space in the [AccountName](config.md#name)
 2. Strip/replace the space [via the ProfileFormat option](#how-to-configure-profileformat)


### What are the purpose of the Tags?

Tags are key/value pairs that you can use to search for roles to assume when
using the [exec](commands.md#exec) command.

The `~/.aws-sso/config.yaml` file supports defining [tags](config.md#tags) at
the `Account` and `Role` levels.  These tags make it easier to manage many
roles in larger scale deployments with lots of AWS Accounts. AWS SSO CLI adds
a number of tags by default for each role and a full list of tags can be viewed
by using the [tags](commands.md#tags) command.

--

## Errors and their meaning

### Error: Invalid grant provided

If you get this error from AWS:

<!-- https://github.com/synfinatic/aws-sso-cli/issues/166 -->
![](https://user-images.githubusercontent.com/1075352/149675666-64512a6a-f252-4841-8222-a2dc1f8f7c1f.png)

Then the most likely cause is you selected the wrong AWS Region for [SSORegion](
config.md#ssoregion) in the config file.

### Error: Unable to save... org.freedesktop.DBus.Properties...

On Linux systems or other places that rely on the FreeDesktop [secret-service](
https://specifications.freedesktop.org/secret-service/latest/re01.html)
you may sometimes receive an error like:

`ERROR   Unable to save RegisterClientData error="the interface org.freedesktop.DBus.Properties does not exist"`

This apparently happens when the underlying FreeDesktop secret-service crashes.
Depending on your OS and setup, running:

`gnome-keyring-daemon -r -d`

as your default (non-root) user, but be sure to check the relevant documentation
with your OS for best practices.

### Error: Unexpected AccessToken failure; refreshing

This can happen when querying AWS for a list of AWS Accounts or Roles and may
indicate that AWS is throttling requests because the number of
[Threads](config.md#Threads) is too high.

Note: Unlike most errors, this one is not always fatal, but it can cause `aws-sso`
to behave very poorly.

### Warning: Exceeded MaxRetry/MaxBackoff. Consider tuning values.

While trying to refresh the cache of accounts and roles, `aws-sso` is exceeding
the rate limits put in place by AWS and that rate limiting is causing
the number of retries to exceed the [MaxRetry](config.md#maxretry) limit.

This typically will happen with large numbers of accounts and multiple threads.

You may wish to consider reducing the number of [Threads](config.md#threads)
to reduce chances of this happening (fewer threads can increase performance
by not incurring the backoff delay penalty) or adjust the MaxRetry and/or
[MaxBackoff](config.md#maxbackoff) parameters.

### Warning: Fetching roles for 46 accounts, this might take a while...

Due to the AWS API and rate limits, users with many AWS Accounts may see
this warning.  

--

## Misc

### What is the story with Homebrew support?

Initially, `aws-sso-cli` was distributed as an [independant tap](
https://github.com/synfinatic/homebrew-aws-sso-cli) but as of
[v1.9.10](https://github.com/synfinatic/aws-sso-cli/blob/main/CHANGELOG.md#v1.9.10) it has been added to homebrew-core.

As of v1.9.10, I will no longer be maintaing the above tap, but because
of the way homebrew works, the version in homebrew-core supercedes the
old tap so no user intervention is necessary.

### How good is the Windows support?

In a word: alpha.

For best experience, I recommend using CommandPrompt (`cmd.exe`) instead of PowerShell
or MINGW64/bash.  Not that you can't use PowerShell or bash, but there are a number of
terminal related issues which cause `aws-sso` to behave incorrectly.
PowerShell and MINGW64/bash users should rely on CLI arguments rather than the
interactive role selector.

[Tracking ticket](https://github.com/synfinatic/aws-sso-cli/issues/189)

Now that [#188](https://github.com/synfinatic/aws-sso-cli/issues/188) has been fixed,
PowerShell users can use the `eval` command to load IAM credentials into their current
shell.

If you are a Windows user and experience any bugs, please open a [detailed bug report](
https://github.com/synfinatic/aws-sso-cli/issues/new?labels=bug&template=bug_report.md).

### How can I say thanks?

Honestly, just send me an email saying thanks or "star" this project in GitHub
is enough thanks.

Occasionally, someone will ask about giving me a few bucks, but I really don't
need any money.  If you still would like to throw a few bucks my way, I'd much
rather you donate to [Second Harvest Food Bank](https://www.shfb.org/) which
is local to me and could put your money to better work than I would.


