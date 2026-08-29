package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"strings"
)

// ecsSslTrustInstructions renders the full set of per-runtime trust
// instructions for the local ECS Server CA at caPath. It is regenerated from
// code every time (never persisted to disk as text), so it can never drift
// out of sync with what this build of aws-sso-cli actually does.
func ecsSslTrustInstructions(caPath, fingerprint string, sans []string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "\nLocal ECS Server CA certificate: %s\n", caPath)
	fmt.Fprintf(&b, "SHA-256 fingerprint: %s\n", fingerprint)
	fmt.Fprintf(&b, "\nThis CA is reused (not regenerated) every time you rerun\n")
	fmt.Fprintf(&b, "'aws-sso setup ecs ssl --self-signed', so you only need to trust it\n")
	fmt.Fprintf(&b, "once per machine/runtime below. Only 'aws-sso setup ecs ssl --rotate-ca'\n")
	fmt.Fprintf(&b, "or '--delete' will require repeating these steps.\n")

	if len(sans) > 0 {
		fmt.Fprintf(&b, "\nAdditional certificate names covered: %s\n", strings.Join(sans, ", "))
	}

	fmt.Fprint(&b, ecsSslTrustMacOS)
	fmt.Fprint(&b, ecsSslTrustLinux)
	fmt.Fprint(&b, ecsSslTrustWindows)
	fmt.Fprint(&b, ecsSslTrustNode)
	fmt.Fprint(&b, ecsSslTrustJVM)
	fmt.Fprint(&b, ecsSslTrustDotNet)
	fmt.Fprint(&b, ecsSslTrustPython)
	fmt.Fprint(&b, ecsSslTrustBotocoreVersion)

	return strings.ReplaceAll(b.String(), "<CA path>", caPath)
}

const ecsSslTrustMacOS = `
== macOS ==
Trust the CA for your user (no sudo required):
  security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db <CA path>

To trust it for every user on the machine instead, add it to the System
keychain (requires sudo):
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <CA path>
`

const ecsSslTrustLinux = `
== Linux ==
Debian/Ubuntu:
  sudo cp <CA path> /usr/local/share/ca-certificates/aws-sso-ecs-ca.crt
  sudo update-ca-certificates

RHEL/Fedora/CentOS:
  sudo cp <CA path> /etc/pki/ca-trust/source/anchors/aws-sso-ecs-ca.pem
  sudo update-ca-trust extract
`

const ecsSslTrustWindows = `
== Windows ==
  certutil -addstore -user Root <CA path>
`

const ecsSslTrustNode = `
== Node.js ==
Unlike AWS_CA_BUNDLE, this is additive to Node's existing trust store, so your
real AWS API calls are unaffected. Set it in the environment of the process
using the SDK (not just your shell):
  NODE_EXTRA_CA_CERTS=<CA path>
`

const ecsSslTrustJVM = `
== Java / JVM ==
  keytool -importcert -alias aws-sso-ecs-ca -keystore <path to cacerts> -file <CA path>
`

const ecsSslTrustDotNet = `
== .NET ==
.NET uses the OS trust store, so no separate step is needed beyond the
macOS/Linux/Windows instructions above.
`

const ecsSslTrustPython = `
== Python / AWS CLI ==
botocore's container-credentials fetcher hardcodes certificate verification
against a bundle it resolves internally: pip's certifi package if importable
in that exact Python environment, otherwise a cacert.pem file vendored
inside the botocore install itself. It ignores both AWS_CA_BUNDLE and the OS
trust store, so trusting this CA anywhere above has no effect on Python or
the AWS CLI. This is tracked upstream: https://github.com/aws/aws-cli/issues/9016

At-your-own-risk workaround (not a real fix — it is silently undone by every
upgrade, and must be repeated for every Python env/AWS CLI install that
talks to this ECS Server). Do NOT assume a bare "python3" on your $PATH is
the same interpreter that runs "aws" — Homebrew, pipx, and the official AWS
CLI v2 installer each bundle their own isolated Python and often don't even
have certifi importable, so botocore silently falls back to its own vendored
cacert.pem instead. Find the actual bundle in use:
  find "$(dirname "$(dirname "$(readlink -f "$(command -v aws)")")")" -name cacert.pem
If that finds nothing, run this with the *same* interpreter "aws" uses
(check its shebang: head -1 "$(command -v aws)"), not just any python3:
  python3 -c "import certifi; print(certifi.where())"
Then append this CA to whichever file you found:
  cat <CA path> >> <bundle path found above>
`

const ecsSslTrustBotocoreVersion = `
== Minimum botocore version ==
If the ECS Server is not bound to loopback, botocore 1.43.0+ is required for
the "https to any hostname" short-circuit; older versions reject non-loopback
hostnames outright regardless of certificate trust.
`
