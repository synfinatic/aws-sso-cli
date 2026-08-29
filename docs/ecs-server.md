# Using ECS Server Mode

## Overview

AWS provides the ability for [ECS Tasks to assume an IAM role](
https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
via an HTTP endpoint defined via the `AWS_CONTAINER_CREDENTIALS_FULL_URI` shell
ENV variable.

All AWS SDK clients using the the same ECS Server container credentials endpoint
URL will utilize the same AWS IAM Role.  Note that this feature is also compatible
with the [HTTP Client Provider](
https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/endpointcreds).

`aws-sso` can emulate this ECS service and allow any process to utilize one or more IAM
roles backed by AWS Identity Center/SSO.

One important distinction between `aws-sso` and this ECS Server, is that the ECS Server
_does not have access to the SecureStore_.  The only SSO or IAM credentials it has
available to it are those you manually load into it's memory.

## Why?

ECS Server emulation exists to aid software developers who wish to test their
applications locally.  Modern software development has moved to containers, for
deploying in Kubernetes (Amazon EKS, etc), Amazon ECS, or one of the [many other
AWS container services](https://docs.aws.amazon.com/decision-guides/latest/containers-on-aws-how-to-choose/choosing-aws-container-service.html).

However, managing multiple AWS API credentials across containers is not easy or
standardized. The limited time usage aspect of AWS SSO/Identity Center managed
credentials only makes it harder.

AWS SSO ECS Server solves that problem by emulating the [AWS ECS method of injecting
API credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
so the only thing you need to do is manage an environment variable in your container.

And since AWS SSO ECS server can run in a container itself, it makes it trivial
to add to your test harness, Docker compose file, etc.

## Security Considerations

The `aws-sso` ECS Server is intended to run on hosts where a single user has access.
The security of your IAM credentials is dependent on nobody else being able to talk
to the server. `aws-sso setup ecs ssl --self-signed` (see below) makes SSL/TLS
practical to enable for most AWS SDKs, but Python/the AWS CLI [cannot currently trust
a private CA for this endpoint](https://github.com/boto/boto3/issues/4188), so
[enabling HTTP Authentication](#ecs-server-http-authentication) remains important if
any of your clients are Python-based.

## Starting the ECS Server

The server runs in the foreground to make it easy to start via systemd and Docker.

`aws-sso ecs server`

Will start the server on `localhost:4144`.   For security purposes, the `aws-sso`
ECS Server will default listen on localhost (127.0.0.1) port 4144.  You may select
an alternative IP/port via the `--bind-ip` and `--port` flags.

### Running the ECS Server in the background

The recommended way to run the ECS server in the background is via the
[aws-sso-cli-ecs-server](https://hub.docker.com/repository/docker/synfinatic/aws-sso-cli-ecs-server/general)
Docker image and the `aws-sso ecs docker [start|stop]` commands as this will
automatically configure your SSL key pair and bearer token from the secure store
in the most secure means possible.

**Note:** For security, by default the Docker container will default listen the
host's loopback interface (`127.0.0.1`), but you can enable it listening on
other interfaces using the `--bind-ip` flag.

### ECS Server security

The ECS Server supports both SSL/TLS encryption as well as HTTP Authentication.
Together, they allow using the `aws-sso` ECS Server on multi-user systems in a
secure manner.

**Important:** Failure to configure HTTP Authentication _and_ SSL/TLS encryption
risks any user on the system running the `aws-sso` ECS Server access to your
AWS IAM authentication tokens.

#### ECS Server SSL Certificate

No public CA (DigiCert, Let's Encrypt, etc.) will issue a certificate for
`localhost`, `127.0.0.1`, or the special ECS credentials IP `169.254.170.2`, so
getting SSL/TLS working here means running your own private CA. `aws-sso` can do
this for you.

```bash
aws-sso setup ecs ssl --self-signed
```

This generates a local CA and a leaf certificate signed by that CA, covering
`localhost`, `127.0.0.1`, `::1`, and `169.254.170.2` by default (add more names
with `--san`, repeatable). Both are stored in the secure store — the same place
`aws-sso ecs server` reads the leaf cert/key from — and the CA certificate (never
its private key) is written to `~/.aws-sso/ecs-ca.pem`. The command then prints
instructions for trusting that CA in your OS and in each AWS SDK runtime.

Rerunning `--self-signed` reuses the existing CA and only issues a new leaf, so
after the first run you never need to re-trust anything — just rerun it whenever
the leaf is close to expiring (397 days) or you've added a new `--san`. Use
`--rotate-ca` only if you need to force a brand new CA, which does
require repeating the trust steps everywhere.

If you need to see the trust instructions again — on a new machine, or because
you forgot them — without generating anything new:

```bash
aws-sso setup ecs ssl --print-ca
```

To remove both the CA and the leaf certificate/key from the secure store:

```bash
aws-sso setup ecs ssl --delete
```

**Important caveat — Python / the AWS CLI:** botocore's container-credentials
fetcher hardcodes certificate verification against a bundle it resolves
internally — pip's `certifi` package if importable in that exact Python
environment, otherwise a `cacert.pem` file vendored inside the botocore
install itself (never the system trust store, and not necessarily the same
file a bare `python3` on your `$PATH` would report — Homebrew, pipx, and the
official AWS CLI v2 installer each bundle their own isolated Python). It
ignores both `AWS_CA_BUNDLE` and the OS trust store, so trusting this (or any)
private CA has no effect on Python or the AWS CLI. This is tracked upstream at
[aws/aws-cli#9016](https://github.com/aws/aws-cli/issues/9016) and can't be
fixed from `aws-sso-cli`. Every other SDK covered by the printed instructions
(Go, Node.js, Java/JVM, .NET) works once its OS or runtime trust store trusts
the CA.

If you lose your certificate, you can print it via:

```bash
aws-sso setup ecs ssl --print
```

**Note:** At this time, there is no way to extract the SSL Private Key from the Secure Store.

#### ECS Server HTTP Authentication

The way to configure HTTP Authentication is with a
[bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1)
as [documented by AWS](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html).

Once you have selected a sufficiently secure secret to use as the bearer token,
you can load it into the Secure Store via:

```bash
aws-sso setup ecs auth --bearer-token '<token>`
```

**Note:** Unlike the `$AWS_CONTAINER_AUTHORIZATION_TOKEN` variable, do not include the
<!--  markdownlint-disable-next-line MD038 -->
prefix `Bearer ` in the token value.

**Important:** You must choose a strong secret value for your bearer token secret!  This is
what prevents anyone else from using your IAM credentials without your permission.  Your bearer
token should be long and random enough to prevent bruteforce attacks.

## Environment variables

### $AWS\_CONTAINER\_CREDENTIALS\_FULL\_URI

AWS clients and `aws-sso` should use:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`

**Note:** If you have configured an SSL certificate as described above, use `https://localhost:4144`.

### $AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI

It is important to _not_ set `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
as that takes precidence for `AWS_CONTAINER_CREDENTIALS_FULL_URI` and it is not
compatible with `aws-sso`.

### $AWS\_CONTAINER\_AUTHORIZATION\_TOKEN

Specify the HTTP Authentication token used to authenticate communication between the
ECS Server and clients (aws-sso and AWS SDK/CLI).  Should be specified
in the format of `Bearer <auth token value>`.

## Selecting a role via ECS Server

Before you can assume a role, you must select an IAM role for the aws-sso ecs
server to present to clients.

`aws-sso ecs load`

Will start the interactive profile selector.  Or you may specify the `--profile`
flag or the `--account` and `--role` flags to specify the role on the command line.

**Note:** Subsequent calls to `aws-sso ecs load` will alter the current IAM Role
for all AWS Client SDKs using it.

## Assuming a role via ECS Server

Ensure you have exported the following shell ENV variable:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/`

**Note:** If you have configured an SSL certificate as described above, use `https://localhost:4144/`.

Then just:

`aws sts get-caller-identity`

should show that you are using the IAM Role you loaded into the ecs server process.

## Determining the current role

Since only one role can be loaded at any given time in the default slot, there
may be times you would like to quickly determine the current role without
resorting to an IAM call:

`aws-sso ecs profile`

will return the currently loaded default profile.

## Unloading role credentials

If you would like to remove the default IAM Role credentials:

`aws-sso ecs unload`

## Storing multiple roles at a time

There may be cases where you would like to make multiple roles available at the
same time without running multiple copies of the ECS server via `aws-sso ecs server`.
Each role is stored in a unique named slot based on the `ProfileName` which is
either set via [Profile](config.md#Profile) or the [ProfileFormat](
config.md#ProfileFormat) configuration options.

### Loading

Specify `aws-sso ecs load --slotted ...` and the individual role will be stored in
it's unique named slot based on it's profile name.

### Listing Profiles

To see a list of profiles loaded in named slots use `aws-sso ecs list`.

### Querying

Accessing the individual credentials is done via the `profile` query parameter:

`export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:4144/slot/ExampleProfileName`

**Note:** If you have configured an SSL certificate as described above, use `httpss://localhost:4144/slot/ExampleProfileName`.

Would utilize the `ExampleProfileName` role.  Note that the `profile` value
value in the URL must be [URL Escaped](https://www.w3schools.com/tags/ref_urlencode.ASP).

### Unloading

To remove a specific IAM Role credential from a named slot in the ECS Server,
you can use:

`aws-sso ecs unload --profile <profile>`

## Kubernetes / Docker Compose Healthcheck

The ECS server exposes a `/healthcheck` endpoint that does **not** require
authentication, making it suitable for k8s probes and Docker Compose `healthcheck:`
commands.

- `GET /healthcheck` — returns `200 OK` when the default slot has valid credentials,
  `503` otherwise.
- `GET /healthcheck/slot/<profile>` — returns `200 OK` when the named slot has valid
  credentials, `503` otherwise.

### Kubernetes example

```yaml
livenessProbe:
  httpGet:
    path: /healthcheck
    port: 4144
  initialDelaySeconds: 5
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /healthcheck
    port: 4144
  initialDelaySeconds: 5
  periodSeconds: 10
```

For a named slot replace the path with `/healthcheck/slot/<profile>` (URL-encode the
profile name if it contains special characters).

### Docker Compose example

Unlike `aws-sso ecs docker start`, `docker compose` does not automatically provision
your configured bearer token or SSL certificate/key into the container. If you have
either configured (via `aws-sso setup ecs auth` and/or `aws-sso setup ecs ssl`), run
`aws-sso ecs docker write-config --disable-ssl` before every `docker compose up` to write the
bearer token to `~/.aws-sso/mnt/docker-ecs`, which the container reads on startup and then
deletes.  See [Why SSL is not needed here](#why-ssl-is-not-needed-here) below for why this
example skips the certificate.
Otherwise the container starts with HTTP Auth disabled, and any client (including
`aws-sso ecs list`) that still sends a bearer token from a previously configured
SecureStore will be rejected with a `403 Forbidden`.

```bash
export AWS_SSO_ECS_TOKEN='<the token you passed to aws-sso setup ecs auth>'
aws-sso ecs docker write-config --disable-ssl
docker compose up &
aws-sso ecs load ...
```

The example below reads `AWS_SSO_ECS_TOKEN` from your shell rather than hard coding the bearer
token into `compose.yaml`, so the secret does not end up in version control.

#### Why SSL is not needed here

`169.254.170.2` is the address AWS uses for the real ECS credential endpoint, so every AWS SDK
and the AWS CLI accept it over **plain HTTP**, the same way they accept `127.0.0.1`.  Assigning
that address to the `aws-sso` container gets you a working setup without an SSL certificate,
which is otherwise more setup than needed for a local endpoint (see
[`--self-signed`](#ecs-server-ssl-certificate) if you do want SSL/TLS here — its default SANs
already include `169.254.170.2`).
Credentials stay on the Docker bridge network and access is controlled by the bearer token.

If you leave off `--disable-ssl` while you have a certificate loaded, the container serves HTTPS
instead, and `myapp` would have to use `https://169.254.170.2:4144` with a certificate the AWS
SDK trusts _for that IP address_ -- which no public CA will issue.

```yaml
# Run `aws-sso ecs docker write-config --disable-ssl` before every `docker compose up`
# to provision the bearer token into ${HOME}/.aws-sso/mnt/docker-ecs (deleted by the
# container after it reads it), otherwise this starts with HTTP Auth disabled and any
# client still sending a configured bearer token will get a 403.
networks:
  aws-sso-ecs:
    driver: bridge
    ipam:
      config:
        - subnet: "169.254.170.0/24"
          gateway: "169.254.170.1"

services:
  aws-sso:
    image: synfinatic/aws-sso-cli-ecs-server:latest
    networks:
      aws-sso-ecs:
        # This special IP address is recognized by the AWS SDKs and AWS CLI
        ipv4_address: "169.254.170.2"
      default: {}
    volumes:
      # necessary for the container to read the security config written by write-config
      - ${HOME}/.aws-sso/mnt:/app/.aws-sso/mnt
    ports:
      # necessary for local management
      - "127.0.0.1:4144:4144"

  myapp:
    image: amazon/aws-cli # replace with your service
    entrypoint: ""
    command: /usr/local/bin/aws sts get-caller-identity
    depends_on:
      aws-sso:
        # ensures this container doesn't start until credentials have been loaded in the ecs server
        condition: service_healthy
    environment:
      AWS_CONTAINER_CREDENTIALS_FULL_URI: http://169.254.170.2:4144
      # must match the token stored via `aws-sso setup ecs auth`.  Omit this (and run
      # `write-config --disable-auth`) only if you are not using HTTP Auth.
      AWS_CONTAINER_AUTHORIZATION_TOKEN: "Bearer ${AWS_SSO_ECS_TOKEN}"
    networks:
      aws-sso-ecs: {}
      default: {}
```

## Errors

The ECS Server API endpoint generates errors with the following JSON format:

```json
{
    "code": "<HTTP error code>",
    "message": "<message>"
}
```

## Authentication

Support for the [$AWS\_CONTAINER\_AUTHORIZATION\_TOKEN](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) environment
variable is supported.

## HTTPS Transport

`aws-sso setup ecs ssl --self-signed` (see [ECS Server SSL Certificate](#ecs-server-ssl-certificate))
covers HTTPS for every AWS SDK runtime except Python/the AWS CLI. That gap is tracked upstream at
[aws/aws-cli#9016](https://github.com/aws/aws-cli/issues/9016) — if you think this feature would be
useful to you, please leave a comment so AWS knows they should prioritize this work.
