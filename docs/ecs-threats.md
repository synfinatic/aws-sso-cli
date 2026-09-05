# ECS Server Threat Model

## Problem Description

The AWS SDK supports fetching the IAM Credentials used for making calls to the AWS API via the
HTTP endpoint defined by the [AWS_CONTAINER_CREDENTIALS_FULL_URI](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
environment variable.

This connection will expose the AWS API credentials for one or more IAM Roles and should
be secured as much as possible.  Unfortunately, the
[AWS SDK only supports public Certificates of Authority](
https://github.com/aws/aws-sdk/issues/774) to enable users to run their own local service
which implements this API on `localhost`.

But [public CA's will not create certificates for localhost](
https://letsencrypt.org/docs/certificates-for-localhost/), nor for `169.254.170.2` (the
special ECS credentials IP, see below).

### SSRF mitigation built into the AWS SDKs

Because `AWS_CONTAINER_CREDENTIALS_FULL_URI` can be pointed at an arbitrary URL, a
misconfigured or compromised environment could leak the `AWS_CONTAINER_AUTHORIZATION_TOKEN`
bearer token to a host the attacker controls. To close this off, AWS SDKs (botocore, the Go SDK,
Java v2, JS v3, etc.) only attach the `Authorization` header when the URI's host is one of a
fixed allow-list:

* `169.254.170.2`, the real ECS Task Metadata/Credentials endpoint
* `169.254.170.23`, the EKS Pod Identity agent
* `fd00:ec2::23`, the IPv6 equivalent of the above
* any loopback address (`127.0.0.0/8`, `::1`)

The first two are AWS-specific addresses within `169.254.0.0/16`, the IPv4 link-local block
reserved by [RFC 3927](https://www.rfc-editor.org/rfc/rfc3927): not routable off the local
link, which is why the SDKs trust that block enough to send the bearer token there.

`169.254.170.23`/`fd00:ec2::23` (EKS Pod Identity) are out of scope for `aws-sso`: it only
emulates the ECS Task Metadata/Credentials endpoint, not the EKS Pod Identity agent, and neither
address is covered by the self-signed cert's SANs (below). `aws-sso`'s own supported set is
narrower than the full SDK allow-list: just loopback (`127.0.0.1`/`::1`) and `169.254.170.2`.

If the host doesn't match, most SDKs still make the request but silently drop the
`Authorization` header rather than refusing outright, so pointing an SDK's
`AWS_CONTAINER_CREDENTIALS_FULL_URI` at a non-allow-listed host doesn't leak the bearer token,
but it also means the ECS Server's HTTP Authentication silently stops working: requests will
fail with a `403`/`401` that looks like a config error rather than a network error. This is
why `aws-sso ecs server` defaults to binding `127.0.0.1`, and why the Docker workflow (see
[Why SSL is not needed here](ecs-server.md#why-ssl-is-not-needed-here)) assigns the container
`169.254.170.2` instead of an arbitrary bridge IP, since both are on the allow-list, so the bearer
token still gets sent. Binding anywhere else works for fetching credentials over plain HTTP,
but silently disables Bearer token auth and can't be covered by the self-signed cert either.
`aws-sso ecs server` logs a warning at startup if `--bind-ip` is set to anything other than
loopback or `169.254.170.2` for exactly this reason. See `docs/ecs-server.md` for the actual
`--bind-ip`/`--self-signed` configuration.

## Solution (implemented)

`aws-sso setup ecs ssl --self-signed` (see [docs/ecs-server.md](
ecs-server.md#ecs-server-ssl-certificate)) generates a private CA and a leaf certificate,
stored in the SecureStore, covering `localhost`, `127.0.0.1`, `::1`, and `169.254.170.2`. This
requires no account, API key, or public DNS registration, and is the actual solution in use
today. It works well for every AWS SDK except Python/the AWS CLI, which is tracked upstream at
[aws/aws-cli#9016](https://github.com/aws/aws-cli/issues/9016).

An earlier draft of this document proposed a hosted CSR-signing web service (user accounts,
per-user DNS records under `aws-sso-cli.org`, ACME DNS-01 signing via Let's Encrypt) as an
alternative to running a private CA. That was never built, and the self-signed CA above covers
the practical need. It remains a hypothetical future option only for zero-touch trust
distribution across multiple users/machines, which a per-machine private CA doesn't solve, and not
something currently planned.

## Attacks

The threat model below covers the two mechanisms `aws-sso ecs server` actually implements: SSL/TLS
(via the self-signed CA above) and HTTP Authentication (Bearer token).

### Attacker has root on the box running aws-sso ECS Server

* Without SSL: Game over.  Can do anything at this point.
* With SSL: same.

### Attacker has non-root on the box running aws-sso ECS Server

* Without SSL: If user has sufficient [capabilities](
https://www.man7.org/linux/man-pages/man7/capabilities.7.html) to inspect
traffic, they can obtain the Bearer Token or AWS API credentials.
* With SSL: No attack; traffic is e2e encrypted and authenticated.

### Attacker has root on the box running aws-sso client

* Without SSL: Game over.  Can do anything at this point.
* With SSL: same.

### Attacker has non-root on the box running the aws-sso client

* Without SSL: If user has sufficient [capabilities](
https://www.man7.org/linux/man-pages/man7/capabilities.7.html) to inspect
traffic, they can obtain the Bearer Token or AWS API credentials.
* With SSL: No attack; traffic is e2e encrypted and authenticated.

### Attacker has root on the box running AWS SDK

* Without SSL: Game over.  Can do anything at this point.
* With SSL: same.

### Attacker has a non-root account on the box running the AWS SDK

* Without SSL: Attacker can open a listener on the same port the user
    runs the ssh port-forwarding.  If the user then ignores the error when they ssh
    over, the attacker can get access to the Bearer Token used by the AWS SDK and
    use that later on to extract AWS API credentials.
  * Mitigate: `ssh -o ExitOnForwardFailure=yes` makes the failed bind fatal rather than a
    warning the user can ignore, which closes this attack even without SSL.
* With SSL: No attack; traffic is e2e encrypted and authenticated.

### Attacker can poison DNS or /etc/hosts

* Without SSL: Attacker can MITM the connection and get access to the Bearer Token
    and AWS API credentials.
  * Mitigate: aws-sso can inspect DNS to ensure IP address is correct
* With SSL: Just a DoS because AWS SDK validates SSL cert before sending the Bearer Token

### Attacker-controlled host tries to leak the Bearer Token via `AWS_CONTAINER_CREDENTIALS_FULL_URI`

* No attack: modern AWS SDKs only send the `Authorization` header (Bearer Token) when the
  target host is `169.254.170.2`, `169.254.170.23`, `fd00:ec2::23`, or loopback (see the
  SSRF mitigation section above). An attacker-controlled `FULL_URI` pointed elsewhere gets no
  token.
  * Caveat: this protection lives in the SDK, not in `aws-sso`, and was only added to some SDKs
    in 2023-2024, so an outdated SDK version may not enforce it. See `docs/ecs-server.md` for the
    minimum botocore version note.

## Suggestions

* Add extensive logging since we're low traffic and anything interesting will show up easily.
* Consider certificate revocation if multi-machine/multi-user trust distribution is ever
  revisited.
