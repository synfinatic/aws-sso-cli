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

This generates (or reuses) a local CA, covering `localhost`, `127.0.0.1`,
`::1`, and `169.254.170.2` by default. Both the CA certificate and its private
key are stored in the secure store, and only there — `aws-sso` never writes a
copy of either one next to your config files. When you need the CA certificate
itself (to hand to the trust-store commands below), export it on demand with
`--print-ca`. The command then prints a short summary — the CA's SHA-256
fingerprint, the `--print-ca` export command, and a link back to this section
for the per-OS/per-runtime trust steps below.

A short-lived (30-day) leaf certificate, signed by that CA, is minted wherever
it's needed — at native `aws-sso ecs server` startup, or by
`aws-sso ecs docker start`/`ecs docker secrets`. It is never stored in the secure
store. `aws-sso ecs server` hands the PEM straight to Go's TLS stack in memory
and never writes it out at all.

The one place it _is_ written out is the Docker path, because a separately
launched container has no other way to get it: `ecs docker secrets` (and
`ecs docker start`) persist it, alongside the bearer token, in the ECS security
file under your config directory (`~/.config/aws-sso/ecs/docker-secret.json`, or
`~/.aws-sso/ecs/docker-secret.json` if you have a legacy `~/.aws-sso`
directory), or wherever `--secrets-dir` / `AWS_SSO_ECS_SECRETS_DIR` points. That
file is 0600, and it persists — `docker compose` owns its own container
lifecycle, so the file has to survive restarts and recreation.

To keep a persisted leaf from quietly aging out, the host-side ECS commands
(`aws-sso ecs load`, `list`, and `profile`) top it up: if the file exists and its
leaf is more than a third of the way through its life, they re-mint it in place
and leave the bearer token untouched. Since the documented workflow already runs
`aws-sso ecs load` after bringing the stack up, in practice the leaf never
approaches expiry. Restart the container to pick up a refreshed leaf.

There's nothing to rotate and nothing to rerun for the leaf itself: as long as
the CA is trusted, every freshly minted leaf is trusted too.

The CA uses a P-256 ECDSA key and is valid for 10 years — it's retained and
reused indefinitely on purpose, since regenerating it (`--rotate-ca`) is the
only thing that requires repeating the trust steps below.

The CA is **name-constrained** (RFC 5280): it carries a critical
`nameConstraints` extension permitting only `localhost`, `127.0.0.0/8`,
`::1/128`, and `169.254.170.2/32`. This matters because the steps below install
it as a trust root. An unconstrained private CA in your trust store would let
anyone holding its private key forge a valid certificate for _any_ site
— `sts.amazonaws.com`, your bank, your company SSO. With the constraints in
place, a leaked CA key can only forge certificates for the loopback and ECS
endpoints the ECS Server itself listens on. It is also marked `pathLen:0`, so
it cannot issue intermediate CAs.

Rerunning `--self-signed` reuses the existing CA, so after the first run you
never need to re-trust anything. Use `--rotate-ca` only if you need to force
a brand new CA, which does require repeating the trust steps everywhere.

`aws-sso ecs server` warns on startup if the CA certificate will expire
within 30 days (or already has), naming `--rotate-ca` as the fix, so you
don't find out from a client's TLS handshake failing instead. The leaf is
always freshly minted, so it can never be close to expiring.

To export the CA certificate — on a new machine, to re-trust it, or just to
inspect it — without generating anything new:

```bash
aws-sso setup ecs ssl --print-ca > ~/aws-sso-ecs-ca.pem
```

`--print-ca` writes the PEM to stdout and nothing else — no fingerprint, no
instructions — so it is safe to redirect to a file or pipe into another
command:

```bash
aws-sso setup ecs ssl --print-ca | openssl x509 -noout -text
```

To remove the CA from the secure store (also disabling SSL/TLS until you
run `--self-signed` again):

```bash
aws-sso setup ecs ssl --delete
```

**Note:** A `docker compose` deployment left running longer than the leaf's
30-day validity without a restart will have its leaf expire mid-run. This is
visible rather than mysterious: the server's `/healthcheck` starts returning
`503` with `"status": "server certificate expired"`, so `docker ps` shows the
container unhealthy and anything using `depends_on: condition: service_healthy`
refuses to start against it. Restart the container to pick up a fresh leaf —
the host-side refresh described above has almost certainly already written one.

##### Trusting the CA per OS and runtime

The CA is reused (not regenerated) every time you rerun `--self-signed`, so you
only need to trust it once per machine/runtime below. Only `--rotate-ca` or
`--delete` will require repeating these steps.

Every command below needs the CA as a file, so start by exporting it:

```bash
aws-sso setup ecs ssl --print-ca > ~/aws-sso-ecs-ca.pem
```

Then substitute that path (`~/aws-sso-ecs-ca.pem`, or wherever you wrote it)
for `<CA path>` below. Once the CA is in the relevant trust store you can
delete the exported file; the trust store keeps its own copy, and you can
always re-export with `--print-ca`.

**macOS** — trust the CA for your user (no sudo required):

```bash
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db <CA path>
```

To trust it for every user on the machine instead, add it to the System
keychain (requires sudo):

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <CA path>
```

**Linux** — Debian/Ubuntu:

```bash
sudo cp <CA path> /usr/local/share/ca-certificates/aws-sso-ecs-ca.crt
sudo update-ca-certificates
```

RHEL/Fedora/CentOS:

```bash
sudo cp <CA path> /etc/pki/ca-trust/source/anchors/aws-sso-ecs-ca.pem
sudo update-ca-trust extract
```

**Windows:**

```bash
certutil -addstore -user Root <CA path>
```

**Node.js** — unlike `AWS_CA_BUNDLE`, this is additive to Node's existing trust
store, so your real AWS API calls are unaffected. Set it in the environment of
the process using the SDK (not just your shell):

```bash
NODE_EXTRA_CA_CERTS=<CA path>
```

**Java / JVM:**

```bash
keytool -importcert -alias aws-sso-ecs-ca -keystore <path to cacerts> -file <CA path>
```

**.NET** — uses the OS trust store, so no separate step is needed beyond the
macOS/Linux/Windows instructions above.

**Important caveat — Python / the AWS CLI:** botocore's container-credentials
fetcher hardcodes certificate verification against a bundle it resolves
internally — pip's `certifi` package if importable in that exact Python
environment, otherwise a `cacert.pem` file vendored inside the botocore
install itself (never the system trust store, and not necessarily the same
file a bare `python3` on your `$PATH` would report — Homebrew, pipx, and the
official AWS CLI v2 installer each bundle their own isolated Python). It
ignores both `AWS_CA_BUNDLE` and the OS trust store, so trusting this (or any)
private CA anywhere above has no effect on Python or the AWS CLI. This is
tracked upstream at [aws/aws-cli#9016](https://github.com/aws/aws-cli/issues/9016)
and can't be fixed from `aws-sso-cli`. Every other SDK covered above (Go,
Node.js, Java/JVM, .NET) works once its OS or runtime trust store trusts the CA.

At-your-own-risk workaround (not a real fix — it is silently undone by every
upgrade, and must be repeated for every Python env/AWS CLI install that talks
to this ECS Server). Do NOT assume a bare `python3` on your `$PATH` is the same
interpreter that runs `aws` — Homebrew, pipx, and the official AWS CLI v2
installer each bundle their own isolated Python. Worse, even asking that exact
interpreter to `import certifi`/`import botocore` isn't reliable: Homebrew's
awscli formula, for example, vendors botocore as `awscli.botocore` (not a
top-level `botocore` module) and doesn't install `certifi` at all, so both
imports fail there even though the vendored `cacert.pem` is sitting right on
disk. Search the filesystem near the `aws` binary instead:

```bash
find "$(dirname "$(dirname "$(readlink -f "$(command -v aws)")")")" -iname cacert.pem
```

If that finds more than one match (some installs vendor both a `certifi` copy
and botocore's own), it's harmless to append the CA to all of them.

Then append this CA to whichever file(s) you found:

```bash
cat <CA path> >> <bundle path found above>
```

**Minimum botocore version:** if the ECS Server is not bound to loopback,
botocore 1.43.0+ is required for the "https to any hostname" short-circuit;
older versions reject non-loopback hostnames outright regardless of
certificate trust.

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
`aws-sso ecs docker secrets --disable-ssl` **once** to write the bearer token into
the ECS security file, which the container reads on startup.  See
[Why SSL is not needed here](#why-ssl-is-not-needed-here) below for why this example
skips the certificate.

```bash
aws-sso setup ecs auth --bearer-token '<a token you choose>'   # once
aws-sso ecs docker secrets --disable-ssl                       # once
docker compose up -d
aws-sso ecs load ...
```

`ecs docker secrets` is one-time setup, not a per-`docker compose up` ritual:
the files it writes persist, so `docker compose down && docker compose up` keeps working. Re-run it
only after changing the bearer token or the CA — and re-running is safe, since a
still-valid leaf certificate is reused rather than replaced.

If the security file is missing, the container **fails to start** with an error naming
the file and the command that creates it. It does not fall back to starting with HTTP
Auth and SSL/TLS silently disabled — a credential server that quietly comes up
unauthenticated is worse than one that refuses to come up. To intentionally run with
neither, pass both `--disable-auth` and `--disable-ssl` to `ecs server`.

`ecs docker secrets` also writes a companion `bearer-token` file containing just the HTTP
`Authorization` header value. The example below bind-mounts that file into `myapp` and
points `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` at it, rather than passing the token as
`AWS_CONTAINER_AUTHORIZATION_TOKEN`: environment variables are visible in
`docker inspect` for the container's whole life and are inherited by every child
process, whereas the file is 0600 and mounted read-only.

`docker compose` cannot work out for itself whether your config lives in
`~/.config/aws-sso` or a legacy `~/.aws-sso`, so the example takes the directory from
`AWS_SSO_ECS_SECRETS_DIR`, defaulting to the XDG location. `ecs docker secrets` prints
the directory it actually used; set the variable if it differs.

`AWS_SSO_ECS_SECRETS_DIR` is read by `aws-sso` itself, not just by `docker
compose` — it is the environment form of `--secrets-dir` — so exporting it is
enough to move the files somewhere else entirely and keep both sides pointing at
the same directory:

```bash
export AWS_SSO_ECS_SECRETS_DIR=~/projects/myapp/.aws-sso-secrets
aws-sso ecs docker secrets --disable-ssl
docker compose up -d
```

`aws-sso` creates that directory 0700 if it does not exist. If you create it
yourself, make sure other users cannot read it: the files hold the bearer token
and the SSL private key in plaintext.

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
# Run `aws-sso ecs docker secrets --disable-ssl` once to provision the bearer
# token into $AWS_SSO_ECS_SECRETS_DIR (the default below assumes the XDG config
# layout; run `ecs docker secrets` to see the path it actually used).  The files
# persist, so this is setup, not something to repeat before every
# `docker compose up`.
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
      # necessary for the container to read the security config written by
      # `ecs docker secrets`; read-only because the server only ever reads it
      - ${AWS_SSO_ECS_SECRETS_DIR:-${HOME}/.config/aws-sso/ecs}:/app/.aws-sso/ecs:ro
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
    volumes:
      # Mount just the token rather than passing it as an environment variable:
      # `docker inspect` exposes env vars for the container's whole life, and every
      # child process inherits them.
      - ${AWS_SSO_ECS_SECRETS_DIR:-${HOME}/.config/aws-sso/ecs}/bearer-token:/run/secrets/aws-sso-token:ro
    environment:
      AWS_CONTAINER_CREDENTIALS_FULL_URI: http://169.254.170.2:4144
      # The AWS SDKs send this file's contents verbatim as the Authorization header,
      # which is why `ecs docker secrets` writes the "Bearer " prefix into it and
      # no trailing newline.  Drop both this and the volume above if you ran
      # `ecs docker secrets --disable-auth`.
      AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: /run/secrets/aws-sso-token
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
