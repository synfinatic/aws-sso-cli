<!-- markdownlint-disable MD033 -->
# Using aws-sso on remote hosts with SSH

This is intended to show how to use your `aws-sso` credentials on a remote/bastion
host, without requring you to install or configure `aws-sso` on that host, while maintaining
security.  Additionally, when you have to authenticate via your SSO provider, that can easily
invoke your local web browser without resorting to printing and clicking on URLs.

## Overview

**Note:** Before going any further, this document assumes you have already
[installed and configured](quickstart.md) aws-sso on your local system.
If not, do that now. :)

Accessing one or more AWS Identity Center based IAM Roles uses the [ECS Server](ecs-server.md)
running locally and then using ssh to forward the port to the remote host.
Security is provided via a bearer token you configure on each side and all traffic is
encrypted over ssh.

**Note:** Configuring the bearer token is mandatory; [SSL](ecs-server.md#ecs-server-security) is
worth enabling on top of it if you can, but it is not the only thing protecting you.  The practical
attack by a non-root user on the remote host -- hijacking the forwarded port -- is closed by
[ExitOnForwardFailure](#why-exitonforwardfailure-matters), described below.  What SSL adds beyond
that is protection from someone capturing loopback traffic, which requires `CAP_NET_RAW` on Linux
or root on macOS -- and an attacker with that much access has better options available to them.

## On your local system

1. Follow the [directions to enable HTTP Authentication and Encryption](ecs-server.md#ecs-server-security).
1. Start the ECS Server:
    1. In a Docker container: `aws-sso ecs docker start`
    1. Or you can use a [screen](https://www.hostinger.com/tutorials/how-to-install-and-use-linux-screen)
or [tmux](https://hamvocke.com/blog/a-quick-and-easy-guide-to-tmux/) session: `aws-sso ecs server`
1. Load your selected IAM credentials into the ECS Server: `aws-sso ecs load --profile=<profile name>`
1. SSH to the remote system using the [-R flag to forward tcp/4144](https://man.openbsd.org/ssh#R)
together with [ExitOnForwardFailure](https://man.openbsd.org/ssh_config#ExitOnForwardFailure):<br>
    `ssh -o ExitOnForwardFailure=yes -R 4144:localhost:4144 <remotehost>`

    **Important:** Do not omit `-o ExitOnForwardFailure=yes`.  See
    [Why ExitOnForwardFailure matters](#why-exitonforwardfailure-matters) below.

## On your remote system (once you have logged in as described above)

**Note:** The following commands assume you are using `bash`.  You may have to tweak for other shells.

1. Tell the AWS SDK how to talk to the ECS Server over SSH:<br>
    `export AWS_CONTAINER_CREDENTIALS_FULL_URI=https://localhost:4144/` (or `http` if you did not enable SSL)
1. Tell the AWS SDK the bearer token secret from the first step on your local system:<br>
    `export AWS_CONTAINER_AUTHORIZATION_TOKEN='Bearer <secret>'`
1. Verify everything works: `aws sts get-caller-identity`

See the [ECS Server documentation](ecs-server.md) for more information about the ECS server and
how to use multiple IAM role credentials simultaneously.

## Why ExitOnForwardFailure matters

By default, `ssh` only prints a warning when it is unable to bind the remote listener and
then continues with the session anyway:

```text
Warning: remote port forwarding failed for listen port 4144
```

That warning is easy to miss, and ignoring it is dangerous.  If another user on the remote
host has already bound tcp/4144, then _their_ listener -- not your ssh tunnel -- is what
`AWS_CONTAINER_CREDENTIALS_FULL_URI` points at.  The AWS SDK will send them the value of
`AWS_CONTAINER_AUTHORIZATION_TOKEN`, which they can then replay against your local ECS Server
to extract your AWS API credentials.

Setting `ExitOnForwardFailure=yes` turns that warning into a fatal error, so ssh terminates
instead of leaving you with a hijacked port.  This closes the attack whether or not you have
SSL/TLS enabled, and costs you nothing.

If you'd rather not type the flag every time, put it in your `~/.ssh/config` for the hosts you
use this way:

```text
Host bastion.example.com
    ExitOnForwardFailure yes
    RemoteForward 4144 localhost:4144
```

**Note:** `sshd` defaults to `GatewayPorts no`, so your forwarded port is bound to the loopback
interface of the remote host and only users with an account on that host can reach it.  On a
shared bastion, that may still be a lot of people.

## Advanced Usage

The above instructions grant any host you ssh to, access to the same AWS IAM Role.  But what if
you want to access multiple roles?

For each role you'd like to access you will need to do two things:

 1. On your local host, load that role into an individual slot in the ECS Server:<br>
    `aws-sso ecs load --slotted --profile <profile name>`
 2. On the remote host, specify the correct URL:<br>
    `export AWS_CONTAINER_CREDENTIALS_FULL=https://localhost:4144/slot/<profile name>`
