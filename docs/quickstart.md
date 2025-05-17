# AWS SSO CLI Quick Start & Installation Guide

## Installation

 * Option 1: [Download binary](https://github.com/synfinatic/aws-sso-cli/releases)
    1. Copy to appropriate location and `chmod 755`
 * Option 2: [Download RPM or DEB package](https://github.com/synfinatic/aws-sso-cli/releases)
    1. Use your package manager to install (Linux only)
 * Option 3: Build & Install via [Homebrew](https://brew.sh)
    1. Run `brew install aws-sso-cli`
        Note: You no longer need to install the hombrew tap as `aws-sso-cli` is
        now part of [homebrew-core](
        https://github.com/Homebrew/homebrew-core/blob/master/Formula/a/aws-sso-cli.rb).
 * Option 4: Build from source:
    1. Install [GoLang](https://golang.org) v1.22+ and GNU Make
    1. Clone this repo
    1. Run `make` (or `gmake` for GNU Make)
    1. Your binary will be created in the `dist` directory
    1. Run `make install` to install in /usr/local/bin
 * Option 5: `go install`:
    1. Install [GoLang](https://golang.org) v1.22+ and GNU Make
    1. `go install github.com/synfinatic/aws-sso-cli/cmd/aws-sso@latest`

Note: macOS binaries must be build on macOS to enable Keychain support.

### Binaries and Code Signatures

The [release binaries and packages](
https://github.com/synfinatic/aws-sso-cli/releases) are not signed with keys
trusted by Apple or Microsoft and may generate warnings on macOS and Windows.

Packages and binaries are however automatically built and signed via
[Github Action](
https://github.com/synfinatic/aws-sso-cli/blob/main/.github/workflows/build-release.yml)
 with my [PGP code signing key](code-sign-key.asc.md).  Note that this is a
_different_ PGP key from the one I use to [sign my commits](commit-sign-key.asc.md).

Users who are paranoid (think SolarWinds) are strongly encouraged to build
binaries themselves.

## Guided Configuration

AWS SSO CLI includes a simple setup wizard to aid in a basic configuration.
This wizard will automatically run the first time you run `aws-sso`.

For more information about configuring `aws-sso` read the
[configuration guide](config.md).

You can re-run through the configuration wizard at any time by running
`aws-sso setup wizard`.  By default, this only does a very basic setup; for a more
advanced setup, use `aws-sso setup wizard --advanced`.

## Enabling auto-completion in your shell

As of v1.9.0, `aws-sso` enhanced it's shell integration and auto-complete
functionality.  The result is an improved [user experience](
commands.md#shell-helpers) but requires a change that is not 100% backwards
compatible.  Please follow the instructions below that match your sitation.

As always, any time you modify your shell init scripts, you must restart your
shell for those changes to take effect.

### First time aws-sso users

Guided setup should of prompted you to install auto-completions, but
you can always re-run it for a different shell:

`aws-sso setup completions -I`

or if you wish to uninstall them:

`aws-sso setup completions -U`

---

### Upgrading from after 1.9.0

Upgrading from versions 1.9.0 or better is just like installing for
first time users:

`aws-sso setup completions -I`

Any changes will be presented to you in diff format and you will be given
the option to accept or reject the changes.

---

### More information

More information on auto-completion can be found in the documentation
for the [setup completions](commands.md#setup-completions) command.

## Use `aws-sso` on the CLI for AWS API calls

There are three preferred ways of using `aws-sso` to make AWS API calls:

 1. Use the `aws-sso-profile` helper script for selecting profiles by name with auto-complete
 1. Use the [exec](commands.md#exec) command for the interactive search
 1. Use the `$AWS_PROFILE` variable

### `aws-sso-profile` helper script

The helper script method allows you to run a command to assume an IAM role
into your current shell.  This method has the advantage of supporting
auto-complete of AWS Profile names and not requiring forking a new shell
which can be confusing.

Full documentation for auto-completion [is available here](
commands.md#shell-helpers).

**Note:** Use of this feature requires
[enabling auto-completion](#enabling-auto-completion-in-your-shell) as described above.

#### Usage

The above defines two new commands, the first of which (`aws-sso-profile`)
allows you to easily assume a role in your current shell with auto-complete
generated AWS Profile names as defined by the [ProfileFormat](
config.md#profileformat) config variable.

The latter (`aws-sso-clear`), clears all the environment variables
installed by `aws-sso-profile`.

If you wish to pass additional arguments to the helper script, you can set
the `$AWS_SSO_HELPER_ARGS` variable.

Pros:

 * Auto-complete makes it easy to use
 * Doesn't fork a new shell

Cons:

 * More complicated one-time setup

---

### Using the `exec` command

Use the [exec](commands.md#exec) command to create a new shell with the
necessary AWS STS environment variables set to access AWS.

#### Usage

Just run: `aws-sso exec` to create a new interactive sub-shell or
`aws-sso exec <command>` to run a command.

Pros:

 * No shell configuration required
 * Allows picking a role via CLI arguments or via the interactive search feature
 * Unlike with the config/`$AWS_PROFILE` integration, it supports opening URLs
    in your browser, printing or copying to your clipboard
 * Allows you to quickly access any role in any account without remembering the
    exact `$AWS_PROFILE` name

Cons:

 * Can be confusing when you start nesting shells inside of each other

---

### Using the `$AWS_PROFILE` variable

If you have existing tooling using [named profiles](
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
and the `$AWS_PROFILE` environment variable, AWS SSO CLI can support that as well.

#### Configuration

Run: `aws-sso setup profiles`

This will add the following lines (example) to your `~/.aws/config` file:

```ini
# BEGIN_AWS_SSO

[profile Name1]
credential_process = /usr/bin/aws-sso process --sso <name> --arn <arn1>

[profile Name2]
credential_process = /usr/bin/aws-sso process --sso <name> --arn <arn2>

# END_AWS_SSO
```

For more information about this feature, see the following sections of the config
docs:

 * [ProfileFormat](config.md#profileformat) and [Profile](config.md#profile)
 * [AutoConfigCheck / ConfigUrlAction](config.md#autoconfigcheck-configurlaction)
 * [ConfigVariables](config.md#configvariables)

#### Usage

Once your `~/.aws/config` file has been modified as described above, you can
access any AWS SSO role the same way you would access a traditional role defined
via AWS API keys: set the `$AWS_PROFILE` environment variable to the name of
the profile.

The only difference is that your API keys are managed via AWS SSO and always
safely stored encrypted on disk!

```bash
export AWS_PROFILE=<name>
```

or for a single command:

```bash
AWS_PROFILE=<name> aws sts get-caller-identity
```

Note that every time the `aws` tool or your code makes a request for the API
credentials, it is calling `aws-sso`.  The first time it does this for a role,
`aws-sso` will talk to AWS STS to get some credentials and then cache the result.
This may (or may not) require human inteaction to authenticate via your SSO
provider.  Future calls will then use the cached STS credentials until they
expire or are [flushed](commands.md#flush).

Pros:

 * Don't need to learn any new commands once you have it setup
 * Is a more consistent user experience when switching from static API keys

Cons:

 * Does not support printing URLs to the console for the user to paste into a browser
 * `aws-sso` must sometimes open a browser to execute a command which can be confusing
 * Must remember the name of every named profile

## AWS Console Access

One of the major benefits of using AWS SSO is having consistent permissions
in the AWS Console as well as via the CLI/API.  Unforunately, using the AWS
Console with multiple accounts and roles can be frustrating because you
can only be logged into a single role at any given time.

AWS SSO CLI solves this problem when you use [Firefox](https://getfirefox.com)
with [Firefox Open URL in Container](
https://addons.mozilla.org/en-US/firefox/addon/open-url-in-container/) v1.0.3 plugin.
This causes each role to have it's own isolated container so you can have
multiple AWS Console sessions active at a time.

Using Firefox containers requires a special configuration in your `~/.aws-sso/config.yaml`
[as described here](config.md#open-url-in-firefox-container).

Regardless if you are using Firefox containers or not, using `aws-sso` to login is straight
forward:

 1. If you have existing AWS API credentials loaded in your shell, typing
        `aws-sso console` will generate a URL to log you into the same role.
 1. Choosing a role can be done via the same CLI options as `exec`
 1. If no CLI options are provided _AND_ you don't have AWS API credentials
        loaded, the tags based search feature will start.
 1. If you have existing AWS API credentials in your shell and you want to login
        to a different role via the tag based search feture, use the `-P` /
        `--prompt` flag.

Demo of how this works:
![FirefoxContainers Demo](
https://user-images.githubusercontent.com/1075352/166165880-24f7c9af-a037-4e48-aa2d-342f2efe5ad7.gif)
