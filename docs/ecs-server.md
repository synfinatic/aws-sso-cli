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

The `aws-sso` ECS Server by default has no SSL or authentication and is intended to
run on hosts where a single user has access.  The security of your IAM credentials
is dependent on nobody else being able to talk to the server.

For multi-user systems, [enabling HTTP Authentication](#ecs-server-http-authentication) makes it
possible to limit who can fetch AWS IAM security tokens from the service.

For multi-user systems where the network/root user is not trusted,
`aws-sso setup ecs ssl --self-signed` (see below) makes SSL/TLS practical to enable for
most AWS SDKs, but Python/the AWS CLI [cannot easily trust a private CA for this endpoint](
https://github.com/boto/boto3/issues/4188).

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

## ECS Server security

The ECS Server supports both SSL/TLS encryption as well as HTTP Authentication.
Together, they allow using the `aws-sso` ECS Server on multi-user systems in a
secure manner.

**Important:** Failure to configure HTTP Authentication _and_ SSL/TLS encryption
risks exposing your AWS IAM authentication tokens to other users on the system.

### ECS Server SSL Certificate

No public CA (DigiCert, Let's Encrypt, etc.) will issue a certificate for
`localhost`, `127.0.0.1`, or the special ECS credentials IP `169.254.170.2`, so
getting SSL/TLS working here means running your own private CA. `aws-sso` can do
this for you.

### Generating the CA and (re)generating the SSL Certificate

```bash
aws-sso setup ecs ssl --self-signed
```

This generates a local CA and a leaf certificate signed by that CA, covering
`localhost`, `127.0.0.1`, `::1`, and `169.254.170.2`. Both are stored in the secure store — the
same place `aws-sso ecs server` reads the leaf cert/key from.

Rerunning `--self-signed` reuses the existing CA and only issues a new leaf, so
after the first run you never need to re-trust anything — just rerun it whenever
the leaf is close to expiring (30 days). If you need to force a brand new CA,
run `--delete`, then `--delete-ca`, then `--self-signed`, which does require
repeating the trust steps everywhere.

Once the leaf has fewer than 5 days of validity left, `aws-sso ecs server` logs a warning
every time new IAM role credentials are loaded, as a reminder to rerun `--self-signed`.

Once you have generated the CA/leaf certificate, future invocations of the aws-sso
ECS Server will automatically disable HTTP and enable HTTPS. There is no flag to
force HTTP while a certificate is stored — run `aws-sso setup ecs ssl --delete`
to disable SSL/TLS instead (see [Deleting the certificate](#deleting-the-certificate)
below).

**Note:** `aws-sso` provides no command to export the CA private key — `--print-ca` prints only the
certificate. How well the key itself is protected is down to your
[secure store](config.md): the OS keychain and 1Password backends encrypt it, while the
`json` store keeps it in plaintext like everything else it holds.

See [Trusting the CA](#trusting-the-ca) below for how to trust this certificate in your OS and
in each AWS SDK runtime.

### Deleting the certificate

To remove just the leaf certificate/key from the secure store, leaving the CA intact:

```bash
aws-sso setup ecs ssl --delete
```

This will automatically disable HTTPS and re-enable HTTP for the ECS Server. Since the
CA is untouched, rerunning `--self-signed` afterward reissues a leaf from the same CA
and nothing needs to be re-trusted.

### Deleting the CA

The CA can only be deleted once the leaf certificate/key is already gone (run
`--delete` first, above):

```bash
aws-sso setup ecs ssl --delete-ca
```

This only removes the CA from the secure store — anything you trusted it in keeps trusting it.
See [Untrusting the CA](#untrusting-the-ca) below, and note the fingerprint printed by
`--self-signed` before you delete the CA: afterwards there is no way to recover it.

### Trusting the CA

First export the local CA certificate to a file (see above):

```bash
aws-sso setup ecs ssl --print-ca > /tmp/ecs-ca.pem
```

The CA is reused (not regenerated) every time you rerun `--self-signed`, so you only need to
export and trust it once per machine/runtime below — only `--delete`, `--delete-ca`, and then
`--self-signed` will require repeating these steps.

`--self-signed` prints the CA's SHA-256 fingerprint on every run. Compare it with the fingerprint
your OS or runtime trust store shows for `aws-sso-cli ECS Server CA` to confirm you trusted the
right certificate, or check the exported file directly:

```bash
openssl x509 -in /tmp/ecs-ca.pem -noout -fingerprint -sha256
```

The CA is scoped as narrowly as X.509 allows: Name Constraints restrict it to only ever sign
certificates for `localhost`, `127.0.0.1`, `::1`, and `169.254.170.2` — the same fixed set of
names the leaf certificate above always uses — an Extended Key Usage of `serverAuth` declares it
usable only for TLS servers, and a path length of 0 prevents it from signing another CA. On a
verifier that enforces those constraints, trusting it system-wide does not grant it (or aws-sso)
the ability to impersonate other sites.

**How much of that is actually enforced depends on the verifier.** RFC 5280 treats a trust anchor
as an input to path validation rather than as a certificate to validate, so honoring a self-signed
root's own name constraints is implementation-specific rather than required.  Covering how each
X.509 library implementation handles this is beyond the scope of this documentation.

#### Do not use `AWS_CA_BUNDLE`

`AWS_CA_BUNDLE` looks like the obvious way to point an AWS SDK at this CA, but it _replaces_ the
trust store used by every AWS API call that SDK makes rather than adding to it:

* the Go SDK reads the bundle into a fresh, empty certificate pool (`resolveCustomCABundle` in
  `aws-sdk-go-v2/config`)
* botocore assigns the one path to `conn.ca_certs`, displacing the `certifi`/vendored bundle it
  would otherwise use

So `export AWS_CA_BUNDLE=/tmp/ecs-ca.pem` makes the process trust this CA and _nothing else_ — its
real calls to `sts.amazonaws.com` and friends then fail certificate verification with
`x509: certificate signed by unknown authority` (Go) or `CERTIFICATE_VERIFY_FAILED` (Python).

Use the per-runtime and per-OS instructions below instead. If you genuinely need one process to
trust both this CA and the public roots through `AWS_CA_BUNDLE`, concatenate them into a single
file and point it at that.

#### Python / AWS CLI

**Important caveat:** botocore's container-credentials fetcher hardcodes
certificate verification against a bundle it resolves internally — pip's `certifi` package if
importable in that exact Python environment, otherwise a `cacert.pem` file vendored inside the
botocore install itself (never the system trust store, and not the same file a bare
`python3` on your `$PATH` would report — Homebrew, pipx, and the official AWS CLI v2 installer
each bundle their own isolated Python). It ignores both `AWS_CA_BUNDLE` and the OS trust store,
so trusting this (or any) private CA has no effect on Python or the AWS CLI. This is tracked
upstream at [aws/aws-cli#9016](https://github.com/aws/aws-cli/issues/9016) and can't be fixed
from `aws-sso-cli`. Every other SDK above (Go, Node.js, Java/JVM, .NET) works once its OS or
runtime trust store trusts the CA.

As a hack, to update the AWS CLI CA store, run:

```bash
cat /tmp/ecs-ca.pem >> $(find "$(dirname "$(dirname "$(readlink -f "$(command -v aws)")")")" -iname cacert.pem)
```

Note that that command must be run every time you update the AWS Python SDK!

**Minimum botocore version:** if the ECS Server is not bound to loopback, botocore 1.43.0+ is
required for the "https to any hostname" short-circuit; older versions reject non-loopback
hostnames outright regardless of certificate trust.

#### Go

Go's `crypto/x509` uses the platform trust store on macOS and Windows, and the usual certificate
files/directories on Linux, so for most programs the OS instructions below are all that is needed.

**Avoid `SSL_CERT_FILE` for this.** Go honors `SSL_CERT_FILE` / `SSL_CERT_DIR` — on Linux always,
and as of Go 1.27 on macOS and Windows as well — but `SSL_CERT_FILE` _replaces_ the trust store
instead of adding to it — the same trap as [`AWS_CA_BUNDLE`](#do-not-use-aws_ca_bundle) above.
Pointing it at the CA makes the process trust this CA and nothing else, so its real AWS API calls
then fail with `x509: certificate signed by unknown authority`.

To trust the CA in one Go program without touching the OS trust store, append it to a copy of the
system pool (`x509.SystemCertPool()` + `AppendCertsFromPEM`) and pass that pool as `RootCAs` in
the `http.Client` you hand to `config.LoadDefaultConfig(ctx, config.WithHTTPClient(client))`.
Unlike the environment variables above, this is additive, so the program's real AWS API calls are
unaffected.

**Note:** the `aws-sso ecs` client commands need no trust configuration at all, but they do not
work the way the paragraph above describes. They read the ECS Server's _leaf_ certificate — not
the CA — from the secure store and put it straight into `RootCAs` (`newClient` in
`cmd/aws-sso/ecs_client_cmd.go`, `NewHTTPClient` in `internal/ecs/client/client.go`). Go's
verifier accepts a leaf that is itself present in the root pool, so this pins that one
certificate rather than trusting the CA to sign anything. `NewHTTPClient` seeds the pool from
`x509.SystemCertPool()`, but that is incidental — on macOS it returns an empty pool — and it is
safe here only because that client talks to nothing but the ECS Server. Don't copy the pattern
into a client that also makes real AWS API calls.

#### Node.js

Unlike [`AWS_CA_BUNDLE`](#do-not-use-aws_ca_bundle), this is additive to Node's existing trust
store, so your
real AWS API calls are unaffected. Set it in the environment of the process using the SDK (not
just your shell):

```bash
mv /tmp/ecs-ca.pem ~/.aws-sso/
export NODE_EXTRA_CA_CERTS=~/.aws-sso/ecs-ca.pem
```

#### Java

```bash
keytool -importcert -alias aws-sso-ecs-ca -keystore <path to cacerts> -file /tmp/ecs-ca.pem
```

#### .NET

Uses the OS trust store, so no separate step is needed beyond the macOS/Linux/Windows
instructions above.

#### macOS

Trust the CA for your user (no sudo required). `-p ssl` limits the trust to the SSL
policy, so the CA is not trusted for code signing, S/MIME, or anything else:

```bash
security add-trusted-cert -d -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db \
  /tmp/ecs-ca.pem
```

To trust it for every user on the machine instead, add it to the System keychain (requires sudo):

```bash
sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain \
  /tmp/ecs-ca.pem
```

#### Debian/Ubuntu

```bash
sudo cp /tmp/ecs-ca.pem /usr/local/share/ca-certificates/aws-sso-ecs-ca.crt
sudo update-ca-certificates
```

#### RHEL/Fedora/CentOS

```bash
sudo cp /tmp/ecs-ca.pem /etc/pki/ca-trust/source/anchors/aws-sso-ecs-ca.pem
sudo update-ca-trust extract
```

#### Windows

```bash
certutil -addstore -user Root %USERPROFILE%\ecs-ca.pem
```

### Untrusting the CA

`aws-sso setup ecs ssl --delete-ca` removes the CA from the secure store, but nothing outside
`aws-sso` learns about that — every copy you installed above stays trusted. Since forcing a new CA
means `--delete`, `--delete-ca`, and then `--self-signed`, rotating without removing the old root
leaves a dead trusted CA behind each time, so undo the steps above before generating a
replacement.

Every generated CA shares the common name `aws-sso-cli ECS Server CA`, so if several have already
accumulated, use the SHA-256 fingerprint to tell them apart. `--self-signed` prints it, and
`openssl x509 -in /tmp/ecs-ca.pem -noout -fingerprint -sha256` reads it back from an exported
copy — but do that _before_ `--delete-ca`, which leaves you with no way to work out which stored
certificate was which.

**macOS** — `-t` removes the trust setting as well as the certificate itself:

```bash
security delete-certificate -t -c "aws-sso-cli ECS Server CA" ~/Library/Keychains/login.keychain-db
```

Use `sudo` and `/Library/Keychains/System.keychain` instead if you trusted it machine-wide. `-c`
requires the name to match exactly one certificate; where it doesn't, select by fingerprint with
`-Z <sha256>` (hex only, no colons).

**Debian/Ubuntu:**

```bash
sudo rm /usr/local/share/ca-certificates/aws-sso-ecs-ca.crt
sudo update-ca-certificates --fresh
```

**RHEL/Fedora/CentOS:**

```bash
sudo rm /etc/pki/ca-trust/source/anchors/aws-sso-ecs-ca.pem
sudo update-ca-trust extract
```

**Windows:**

```bash
certutil -delstore -user Root "aws-sso-cli ECS Server CA"
```

**Java:**

```bash
keytool -delete -alias aws-sso-ecs-ca -keystore <path to cacerts>
```

**Node.js:** unset `NODE_EXTRA_CA_CERTS` (or point it at something else) in the environment of the
process using the SDK, and delete `~/.aws-sso/ecs-ca.pem`.

**Go and .NET** use the OS trust store, so the OS steps above are all that is needed.

## ECS Server HTTP Authentication

The way to configure HTTP Authentication is with a
[bearer token](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1)
as [documented by AWS](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html).

Once you have selected a sufficiently secure secret to use as the bearer token,
you can load it into the Secure Store via:

```bash
aws-sso setup ecs auth --bearer-token '<token>`
```

Once loaded, all future invocations of the aws-sso ECS Server will require a bearer token to
read/write to the service.  The aws-sso client will automatically provide the bearer token
by reading the SecureStore, but you will need to configure any other AWS SDK/cli tool to
use it to read loaded IAM role credentials.

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
as that takes precedence for `AWS_CONTAINER_CREDENTIALS_FULL_URI` and it is not
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

* `GET /healthcheck` — returns `200 OK` when the default slot has valid credentials,
  `503` otherwise.
* `GET /healthcheck/slot/<profile>` — returns `200 OK` when the named slot has valid
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
`aws-sso ecs docker write-secrets` before every `docker compose up` to write whatever is
currently in the SecureStore to `~/.aws-sso/mnt/docker-ecs`, which the container reads
on startup and then deletes. This example intentionally has no SSL certificate
configured (see [Why SSL is not needed here](#why-ssl-is-not-needed-here) below) — if
you previously ran `--self-signed`, run `aws-sso setup ecs ssl --delete` first so
`write-secrets` has no certificate to pick up.
Otherwise the container starts with HTTP Auth disabled, and any client (including
`aws-sso ecs list`) that still sends a bearer token from a previously configured
SecureStore will be rejected with a `403 Forbidden`.

```bash
export AWS_SSO_ECS_TOKEN='<the token you passed to aws-sso setup ecs auth>'
aws-sso ecs docker write-secrets
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

If you still have a certificate loaded (run `aws-sso setup ecs ssl --delete` to remove
it), the container serves HTTPS instead, and `myapp` would have to use
`https://169.254.170.2:4144` with a certificate the AWS SDK trusts _for that IP
address_ -- which no public CA will issue.

```yaml
# Run `aws-sso ecs docker write-secrets` before every `docker compose up` to provision
# the bearer token into ${HOME}/.aws-sso/mnt/docker-ecs (deleted by the container after
# it reads it), otherwise this starts with HTTP Auth disabled and any client still
# sending a configured bearer token will get a 403.
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
      # necessary for the container to read the security config written by write-secrets
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
      # `write-secrets --disable-auth`) only if you are not using HTTP Auth.
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
