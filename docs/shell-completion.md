# AWS SSO Shell Completion 

For version 1.9.0, `aws-sso` enhanced it's shell integration and auto-complete
functionality.  The result is an improved user experience (using 
[commands.md#aws-sso-profile](aws-sso-profile)) but requires a change that
may not be 100% backwards compatible.

## Differences

Versions >= v1.9.0 support auto-complete for the `aws-sso` command as well
as the [aws-sso-profile](commands.md#aws-sso-profile) and [aws-sso-clear](
commands.md#aws-sso-clear) which allow you to assume IAM roles in your 
current shell with auto-complete for the profile name.

The auto-complete that was shipped with < v1.9.0 is fully compatible with
newer versions, but does not support the new features.

At this time, the new shell helper functions introduced in v1.9.0 are only
supported in bash.

## New Installs

If you are a new user of `aws-sso` and wish to enable auto-complete in your shell,
just run `aws-sso completions --install`, review the diff of the proposed change,
and accept the result.


## Upgrading from an older version to v1.9.0+

It is _recommended_ that you first uninstall the old auto-complete code 
before installing the new code.  To do so you may run
`aws-sso completions --uninstall-pre-19` __OR__ manually edit your shell 
config file and remove the block that is described below.

Once the old code is removed you may run `aws-sso completions --install`,
review the diff of the proposed change, and accept the result.

## Shell Config for Versions < v1.9.0

These versions support auto-complete for the `aws-sso` command itself.

There is an `install-completions` command which supports bash, fish and zsh 
shells and writes one of the following blocks.

### bash

On MacOS/Darwin, this will be installed in `~/.bash_profile`.  On other systems,
it will be installed in the first file it finds in the list:

 * `~/.bashrc`
 * `~/.bash_profile`
 * `~/.bash_login`
 * `~/.profile`

```bash
complete -C /usr/local/bin/aws-sso aws-sso
```

### zsh

This will be installed in `~/.zshrc`:

```bash
autoload -U +X bashcompinit && bashcompinit

complete -o nospace -C /usr/local/bin/aws-sso aws-sso
```

### fish 

This will be installed in either:

 * `~/${XDG_CONFIG_HOME}/fish`
 * `~/.config/fish`

```bash
function __complete_aws-sso
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    /usr/local/bin/aws-sso
end
complete -f -c aws-sso -a "(__complete_aws-sso)"
```
