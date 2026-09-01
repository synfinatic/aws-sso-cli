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

// ecsSslTrustDocsURL points at the per-OS/per-runtime trust instructions
// (including the Python/AWS CLI caveat) that used to be printed in full by
// this command. Keeping the full text out of the terminal keeps `--self-signed`
// output short; the docs are the single source of truth for the actual steps.
const ecsSslTrustDocsURL = "https://synfinatic.github.io/aws-sso-cli/latest/ecs-server/#trusting-the-ca-per-os-and-runtime"

// ecsSslTrustInstructions renders a short summary of the local ECS Server CA:
// its fingerprint, how to export the certificate itself, and a link to the full
// per-OS/per-runtime trust instructions. The CA lives only in the secure store,
// so the export step is `--print-ca` rather than a path on disk.
func ecsSslTrustInstructions(fingerprint string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "\nLocal ECS Server CA fingerprint (SHA-256): %s\n", fingerprint)

	fmt.Fprintf(&b, "\nTo export the CA certificate for your trust store:\n")
	fmt.Fprintf(&b, "  aws-sso setup ecs ssl --print-ca > aws-sso-ecs-ca.pem\n")

	fmt.Fprintf(&b, "\nFor per-OS/per-runtime trust instructions see:\n")
	fmt.Fprintf(&b, "  %s\n", ecsSslTrustDocsURL)

	return b.String()
}
