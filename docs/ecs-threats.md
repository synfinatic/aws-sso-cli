# ECS Server Threat Model

## Problem Description

The AWS SDK supports fetching the IAM Credentials used for making calls to the AWS API
the HTTP endpoint defined by the [AWS_CONTAINER_CREDENTIALS_FULL_URI](
https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
environment variable.

This connection will expose the AWS API credentials for one or more IAM Roles and should
be secured as much as possible.  Unfortunately, the
[AWS SDK only supports public Certificates of Authority](
https://github.com/aws/aws-sdk/issues/774) to enable users to run their own local service
which impliments this API on `localhost`.

But [public CA's will not create certificates for localhost](
https://letsencrypt.org/docs/certificates-for-localhost/).

## Solution

In order to support `aws-sso` users who wish to run their own endpoint for
`AWS_CONTAINER_CREDENTIALS_FULL_URI`, we need to create a new public web service which:

---
Scenario: A user wishes to create an account

* Given: A new user who has never enabled SSL before
* When: The user chooses a unique username and password
  * And: Provides a valid email address
* Then: The service creates an account for the user

Note: I generally need to think about the onboarding workflow so this may change.

---
Scenario: A user wishes to register a FQDN for a SSL certificate

* Given: A valid user who has logged in
* When: The user chooses a _unique hostname_ for `aws-sso-cli.org`
* Then: Service creates a DNS A record for _hostname.aws-sso-cli.org_ pointing to `127.0.0.1`
  * And: The user runs the command locally: `aws-sso setup ecs cert fqdn <fqdn>`

---
Scenario: A user wishes to enable CSR signing for the ECS Server certificates

* Given: A valid user who has logged in
* When: The user asks for a new API Key via the web interface
* Then: Web service generates a new API key for the user
  * And: The user runs the command locally `aws-sso setup ecs cert api-key <api key>`

---
Scenario: A user wishes to get a signed certificate from the web service

* Given: A valid API key for a user has been configured
* When: The user runs `aws-sso setup ecs cert sign-csr`
* Then: A new private key / certificate signing request will be generated locally
  * And: The private key will be stored in the SecureStore
  * And: The CSR will be uploaded to the webservice, using the configured API key for authentication

---
Scenario: A user has requested a signed certificate from the web service

* Given: The user has run `aws-sso setup ecs cert sign-csr`
* When: The service validates the API key is assigned to the FQDN in the CSR
* Then: The service asks Let's Encrypt to sign the CSR via ACME DNS-01
  * And: Let's Encrypt signs the CSR
  * And: Service returns the signed Certificate to the user.

---
Scenario: A user has their own CA they'd like to use to sign the certificate

* Given: The user does not wish to use the public web service to manage their certificate
* When: A user runs `aws-sso setup ecs cert export-csr`
* Then: A new private key / certificate signing request will be generated locally
  * And: The private key will be stored in the SecureStore
  * And: The CSR will be written to a file

---
Scenario: A user has signed the CSR with their own CA

* Given: The user has exported a CSR and has had it signed by a CA
* When: The user runs `aws-sso setup ecs cert load <file>`
* Then: `aws-sso` will store the certificate for the ECS Server

---
Scenario: A user wishes to use ECS Server in SSL mode

* Given: `aws-sso` has a valid private key and certificate configured
* When: The user runs the command `aws-sso ecs docker start`
* Then: The ECS Server runs locally
  * And: Uses the configured SSL private key/certificate
  * And: Uses the configured Bearer Token

---
Scenario: A user wishes to use the ECS Server in SSL mode

* Given: The user is locally running the ECS Server in SSL Mode
  * And: The user has configured a Bearer Token for the AWS SDK
  * And: The user has loaded one or more AWS API credentials via `aws-sso ecs load ...`
* When: The user has defined `AWS_CREDENTIALS_FULL_URI=https://<fqdn>:4144` in the current shell
  * And: The AWS SDK attempts to connect to the ECS Server via `127.0.0.1:4144` to retrive the AWS API credentials
* Then: The connection to retrieve the AWS API credentials will be e2e encrypted
  * And: The AWS SDK will use SSL to verify the identity of the ECS Server
  * And: The ECS Server will use the Bearer Token to verify the identiy of the AWS SDK
  * And: The ECS Server will provide the requested API credentials
  * And: The AWS SDK will use the provided AWS API credentials in its request

---
Scenario: A user wishes to use the AWS SDK on a remote host

* Given: The user is locally running the ECS Server in SSL Mode
  * And: The user has configured a Bearer Token for the AWS SDK
  * And: The user has loaded one or more AWS API credentials via `aws-sso ecs load ...`
* When: The user runs `ssh -R 4144:localhost:4144 <host>`
  * And: The user has defined `AWS_CREDENTIALS_FULL_URI=https://<fqdn>:4144` in the remote shell
  * And: The AWS SDK attempts to connect to the ECS Server via `127.0.0.1:4144` to retrive the AWS API credentials
* Then: The connection will be proxied by ssh to the users local system where the ECS Server is running
  * And: The AWS SDK will use SSL to verify the identity of the ECS Server
  * And: The ECS Server will use the Bearer Token to verify the identiy of the AWS SDK
  * And: The ECS Server will provide the requested API credentials
  * And: The AWS SDK will use the provided AWS API credentials in its request

---

## Attacks

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
* With SSL: No attack; traffic is e2e encrypted and authenticated.

### Attacker can posion DNS or /etc/hosts

* Without SSL: Attacker can MITM the connection and get access to the Bearer Token
    and AWS API credentials.
  * Mitigate: aws-sso can inspect DNS to ensure IP address is correct
* With SSL: Just a DoS because AWS SDK validates SSL cert before sending the Bearer Token

### Attacker can DoS the certificate signing service

* Attacker can prevent users from getting updated certificates when they expire.
  * Mitigations:
    * Consider configurable endpoints
    * Use CloudFlare

### Attacker can exploit the certificate signing service

* Attacker can issue their own certificate for hostname.aws-sso-cli.org
* Attacker can update DNS and point hostname.aws-sso-cli.org at a different IP than 127.0.0.1
  * Mitigate: aws-sso client can validate DNS record is valid
* Attacker can inject bad data and modify the database of users
* Attacker can steal API Key of users to sign CSRs
  * Mitigate: use public key auth to mitigate
* Lookup "click jacking" -- run Burp scanner

## Suggestions

* Examine need for certificate revocation for users.
* Look into a private/public cert method of API Key for authentication so people can't dump my database
and issue certs for anyone.
* Add extensive logging since we're low traffic and anything interesting will show up easily
* Use Burp scanner/suite to do a pen test
* Examine what free security options CloudFlare & Fly.io? provide
