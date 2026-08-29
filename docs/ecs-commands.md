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

 Generates (or reuses) a local CA and issues a leaf certificate for the ECS
 Server, saving both to the SecureStore. See
 [ecs-server.md](ecs-server.md#ecs-server-ssl-certificate) for the full walkthrough,
 including per-runtime trust instructions and the Python/AWS CLI caveat.

 Flags:

* `--self-signed` -- Generate (or reuse) a local CA and issue a new leaf certificate for the
  ECS Server. This is the default action when no other flag is given.
* `--san` -- Additional DNS name or IP address to include in the self-signed leaf certificate (repeatable)
* `--print-ca` -- Prints the local self-signed CA certificate and re-prints trust instructions
* `--print` -- Prints the current SSL (leaf) certificate
* `--delete` -- Disables SSL and deletes the current SSL certificate/private key and CA from the Secure Store

---

### ecs docker start

Starts the ECS Server in a Docker container.

Flags:

* `--disable-auth` -- Disables HTTP Auth, even if a bearer token is available
* `--disable-ssl` -- Disables SSL/TLS, even if a certificate and private key are available.
* `--bind-ip` -- IP address to bind the service to.  (default 127.0.0.1)
* `--port` -- Port to listen on.  (default 4144)
* `--image` -- Docker image to use.  (default `synfinatic/aws-sso-cli-ecs-version`)
* `--version` -- Version of the docker image to use (default matches `aws-sso` binary version)

---

### ecs docker stop

Stops the ECS Server Docker container.

---

### ecs docker write-config

Writes the bearer token and/or SSL certificate/private key from the SecureStore
to the security config file (`~/.aws-sso/mnt/docker-ecs`) read by the ECS Server
Docker image on startup, without starting or managing a container itself. Use
this when launching the ECS Server container via `docker compose` or another
tool instead of `ecs docker start`, so the container still picks up your
configured HTTP Auth and/or TLS material. The file is deleted by the container
once read, so re-run this command before every `docker compose up`.

Flags:

* `--disable-auth` -- Do not include the HTTP Auth bearer token in the config file
* `--disable-ssl` -- Do not include the SSL cert/key in the config file

---

### ecs list

List the AWS Profiles stored in the ECS Server.

Flags:

* `--server` -- host:port of the ECS Server (default `localhost:4144`)

---

### ecs load

Load the AWS IAM Role credentials into the ECS Server for clients to use.

Flags:

* `--arn <arn>`, `-a` -- ARN of role to assume (`$AWS_SSO_ROLE_ARN`)
* `--account <account>`, `-A` -- AWS AccountID of role to assume (`$AWS_SSO_ACCOUNT_ID`)
* `--role <role>`, `-R` -- Name of AWS Role to assume (requires `--account`) (`$AWS_SSO_ROLE_NAME`)
* `--profile <profile>`, `-p` -- Name of AWS Profile to assume
* `--server` -- host:port of the ECS Server (default `localhost:4144`)
* `--slotted` -- Load the IAM credentials into a unique slot using the ProfileName as the key

You can provide `--profile` or `--arn` or (`--account` and `--role`) to specify the IAM role to load.

If you do not specify `--slotted`, the role will be loaded into the default URL path at `/`.  If you
would like to load multiple roles, specify `--slotted` and the role will be loaded into `/slot/<profile name>`

---

### ecs profile

Fetches the ProfileName of the role stored in the default slot of the ECS Server.

Flags:

* `--slotted` -- Load the IAM credentials into a unique slot using the ProfileName as the key

---

### ecs server

Starts the ECS Server in the foreground.

Flags:

* `--disable-auth` -- Disables HTTP Authentication, even if a Bearer Token is available
* `--disable-ssl` -- Disables SSL/TLS, even if a certificate and private key are available

---

### ecs unload

Removes the AWS IAM Role credentials from the ECS Server and makes them unavailable to any clients to use.

Flags:

* `--profile <profile>`, `-p` -- Slot of AWS Profile to unload
* `--server` -- host:port of the ECS Server (default `localhost:4144`)

By default, this will unload the IAM credentials for the default role.  Passing in
`--profile <profile name>` will unload the credentials in the named slot.
