# ECS Commands

For information about the ECS Server functionality, see the [ecs-server](ecs-server.md) page.

## Commands

### setup ecs

#### setup ecs auth

Configures the HTTP Authentication BearerToken.  Once set, all future client
requests to the ECS Server will need to provide the correct credentials.  
`aws-sso` utilizing the same SecureStore as the ECS Server will automatically
provide the necessary HTTP Auth header, but other AWS clients utilizing the
AWS SDK will require [$AWS_CONTAINER_AUTHORIZATION_TOKEN](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) to be set.

Flags:

* `--bearer-token` -- Specify the bearer token secret.
* `--delete` -- Delete the bearer token and disable authentication.

---

#### setup ecs ssl

 Generates (or reuses) a local CA for the ECS Server, saving it to the
 SecureStore. The leaf certificate is minted fresh in memory wherever it is
 needed and is never stored. See
 [ecs-server.md](ecs-server.md#ecs-server-ssl-certificate) for the full walkthrough,
 including per-runtime trust instructions and the Python/AWS CLI caveat.

 Flags:

* `--self-signed` -- Generate (or reuse) a local CA for the ECS Server. This is the default
  action when no other flag is given.
* `--rotate-ca` -- Force generation of a brand new CA instead of reusing the existing one (requires
  re-trusting on every client)
* `--print-ca` -- Prints the local CA certificate PEM to stdout and nothing else, so it can be
  redirected to a file for your trust store:
  `aws-sso setup ecs ssl --print-ca > ~/aws-sso-ecs-ca.pem`
* `--delete` -- Disables SSL and deletes the CA certificate/private key from the Secure Store

---

### ecs docker start

Starts the ECS Server in a Docker container.

Flags:

* `--disable-auth` -- Disables HTTP Auth, even if a bearer token is available
* `--disable-ssl` -- Disables SSL/TLS, even if a certificate and private key are available.
* `--bind-ip` -- IP address to bind the service to.  (default 127.0.0.1)
* `--port` -- Port to listen on.  (default 4144)
* `--image` -- Docker image to use.  (default `synfinatic/aws-sso-cli-ecs-server`)
* `--version` -- Version of the docker image to use (default matches `aws-sso` binary version)
* `--default <profile>`, `-d` -- Profile name to load as default credentials on start
* `--secrets-dir` -- Bind-mount this directory into the container instead of the default
  (env: `AWS_SSO_ECS_SECRETS_DIR`).  See
  [Choosing where the files go](#choosing-where-the-files-go).

---

### ecs docker stop

Stops the ECS Server Docker container.

Flags:

* `--version` -- Version of the docker image to stop (default `latest`)

---

### ecs docker secrets

Writes the bearer token and/or SSL certificate/private key from the SecureStore
to the ECS security config file (`~/.config/aws-sso/ecs/docker-secret.json`, or
`~/.aws-sso/ecs/docker-secret.json` if you have a legacy `~/.aws-sso`
directory) read by the ECS Server Docker image on startup, without starting or
managing a container itself. Use this when launching the ECS Server container
via `docker compose` or another tool instead of `ecs docker start`, so the
container still picks up your configured HTTP Auth and/or TLS material.

This is one-time setup: the file persists, so container restarts and recreation
keep working. Re-run it only after changing the bearer token or the CA.
Re-running is safe — a still-valid leaf certificate is reused rather than
replaced, so a running container's certificate is not invalidated.

Unless `--disable-auth` is given, it also writes a companion `bearer-token` file
in the same directory containing just the HTTP `Authorization` header value, for
client containers using `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`.

Both files are mode 0600. The command prints the directory to bind-mount into
the container.

Flags:

* `--disable-auth` -- Do not include the HTTP Auth bearer token in the config file
* `--disable-ssl` -- Do not include the SSL cert/key in the config file
* `--secrets-dir` -- Write the files to this directory instead of the default
  (env: `AWS_SSO_ECS_SECRETS_DIR`).  See below.

#### Choosing where the files go

`--secrets-dir` overrides the default location for every `ecs` command that
touches these files: `ecs docker secrets` writes them there, `ecs docker start`
bind-mounts that directory into the container, and `ecs load`/`list`/`profile`
refresh the certificate there as it ages.  Set it once via
`AWS_SSO_ECS_SECRETS_DIR` so a `docker compose` stack and the CLI agree.

A relative path is resolved against the working directory, since Docker bind
mounts require an absolute source.  aws-sso creates the directory 0700 if it
does not exist; a directory you created yourself keeps the permissions you gave
it, so make sure it is not readable by other users -- the files hold the bearer
token and the SSL private key in plaintext.

---

### ecs list

List the AWS Profiles stored in the ECS Server.

Flags:

* `--server` -- host:port of the ECS Server (default `localhost:4144`) (`$AWS_SSO_ECS_SERVER`)

---

### ecs load

Load the AWS IAM Role credentials into the ECS Server for clients to use.

Flags:

* `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
* `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
* `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)
* `--profile <profile>`, `-p` -- Name of AWS Profile to assume
* `--sts-refresh` -- Force refresh of STS Token Credentials
* `--server` -- host:port of the ECS Server (default `localhost:4144`) (`$AWS_SSO_ECS_SERVER`)
* `--slotted`, `-s` -- Load the IAM credentials into a unique slot using the ProfileName as the key

You can provide `--profile` or `--arn` or (`--account` and `--role`) to specify the IAM role to load.

If you do not specify `--slotted`, the role will be loaded into the default URL path at `/`.  If you
would like to load multiple roles, specify `--slotted` and the role will be loaded into `/slot/<profile name>`

---

### ecs profile

Fetches the ProfileName of the role stored in the default slot of the ECS Server.

Flags:

* `--server` -- host:port of the ECS Server (default `localhost:4144`) (`$AWS_SSO_ECS_SERVER`)

---

### ecs server

Starts the ECS Server in the foreground.

Flags:

* `--bind-ip` -- IP address to bind the service to.  (default 127.0.0.1)
* `--port` -- Port to listen on.  (default 4144)
* `--default <profile>`, `-d` -- Profile name to load as default credentials on start
* `--disable-auth` -- Disables HTTP Authentication, even if a Bearer Token is available
* `--disable-ssl` -- Disables SSL/TLS, even if a certificate and private key are available

---

### ecs unload

Removes the AWS IAM Role credentials from the ECS Server and makes them unavailable to any clients to use.

Flags:

* `--profile <profile>`, `-p` -- Slot of AWS Profile to unload
* `--server` -- host:port of the ECS Server (default `localhost:4144`) (`$AWS_SSO_ECS_SERVER`)

By default, this will unload the IAM credentials for the default role.  Passing in
`--profile <profile name>` will unload the credentials in the named slot.
