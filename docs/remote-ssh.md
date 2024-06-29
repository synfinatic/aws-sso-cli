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

**Note:** The root user or anyone with [CAP_NET_RAW or CAP_NET_ADMIN](https://man7.org/linux/man-pages/man7/capabilities.7.html)
will be able to intercept the HTTP traffic on either endpoint and obtain the bearer token
and/or any IAM Credentials stored in the ECS Server if you have not [enabled SSL](ecs-server.md#ecs-server-security).

## On your local system

1. Configure a [bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1)
for security to prevent unauthorized use of your IAM credentials:<br>
`aws-sso ecs bearer-token -t 'Bearer <secret>'`
1. Start the ECS Server (preferably in a [screen](https://www.hostinger.com/tutorials/how-to-install-and-use-linux-screen)
or [tmux](https://hamvocke.com/blog/a-quick-and-easy-guide-to-tmux/) session):
`aws-sso ecs run`
1. Load your selected IAM credentials into the ECS Server:<br>
`aws-sso ecs load --profile=<aws profile name>`
1. SSH to the remote system using the [-R flag to forward tcp/4144](https://man.openbsd.org/ssh#R):<br>
`ssh -R 4144:localhost:4144 <remotehost>`

## On your remote system (once you have logged in as described above)

**Note:** The following commands assume you are using `bash`.  You may have to tweak for other shells.

1. Tell the AWS SDK how to talk to the ECS Server over SSH:<br>
`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`
1. Tell the AWS SDK the bearer token secret from the first step on your local system:<br>
`export AWS_CONTAINER_AUTHORIZATION_TOKEN='Bearer <secret>'`
1. Verify everything works:
`aws sts get-caller-identity`

**Note:** If you have [loaded an SSL certificate/private](ecs-server.md#ecs-server-security)
key into `aws-sso` use: `export AWS_CONTAINER_CREDENTIALS_FULL_URI=https://localhost:4144/` instead.

**Important:** You must choose a strong secret value for your bearer token secret!  This is
what prevents anyone else from using your IAM credentials without your permission.  Your bearer
token should be long and random enough to prevent bruteforce attacks.

See the [ECS Server documentation](ecs-server.md) for more information about the ECS server and
how to use multiple IAM role credentials simultaneously.