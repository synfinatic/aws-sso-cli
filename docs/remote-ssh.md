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

**Warning:** Running [without SSL](ecs-server.md#ecs-server-security) is not recommend as it
may allow even a non-root user on the remote host to steal your AWS API credentials.

## On your local system

1. Follow the [directions to enable HTTP Authentication and Encryption](ecs-server.md#ecs-server-security).
1. Start the ECS Server:
    1. In a Docker container: `aws-sso ecs docker start`
    1. Or you can use a [screen](https://www.hostinger.com/tutorials/how-to-install-and-use-linux-screen)
or [tmux](https://hamvocke.com/blog/a-quick-and-easy-guide-to-tmux/) session: `aws-sso ecs server`
1. Load your selected IAM credentials into the ECS Server: `aws-sso ecs load --profile=<profile name>`
1. SSH to the remote system using the [-R flag to forward tcp/4144](https://man.openbsd.org/ssh#R):
    `ssh -R 4144:localhost:4144 <remotehost>`

## On your remote system (once you have logged in as described above)

**Note:** The following commands assume you are using `bash`.  You may have to tweak for other shells.

1. Tell the AWS SDK how to talk to the ECS Server over SSH:<br>
    `export AWS_CONTAINER_CREDENTIALS_FULL_URI=https://localhost:4144/` (or `http` if you did not enable SSL)
1. Tell the AWS SDK the bearer token secret from the first step on your local system:<br>
    `export AWS_CONTAINER_AUTHORIZATION_TOKEN='Bearer <secret>'`
1. Verify everything works: `aws sts get-caller-identity`

See the [ECS Server documentation](ecs-server.md) for more information about the ECS server and
how to use multiple IAM role credentials simultaneously.

## Advanced Usage

The above instructions grant any host you ssh to, access to the same AWS IAM Role.  But what if
you want to access multiple roles?

For each role you'd like to access you will need to do two things:

 1. On your local host, load that role into an individual slot in the ECS Server:<br>
    `aws-sso ecs load --slotted --profile <profile name>`
 2. On the remote host, specify the correct URL:<br>
    `export AWS_CONTAINER_CREDENTIALS_FULL=https://localhost:4144/slot/<profile name>`
