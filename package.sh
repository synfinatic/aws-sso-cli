#!/usr/bin/env bash

: ${VERSION?}

function package() {
    local CPU=$1
    case $CPU in
    amd64)
        local ARCH=x86_64
        ;;
    arm64)
        local ARCH=arm64
        ;;
    *)
        echo "Invalid CPU=$CPU"
        exit 1
    esac
    cat <<EOF >/root/package.yaml
meta:
  description: AWS SSO CLI
  vendor: Aaron Turner
  maintainer: Aaron Turner
  license: GPLv3
  url: https://github.com/synfinatic/aws-sso-cli
files:
  "/usr/bin/aws-sso":
    file: /root/dist/aws-sso-${VERSION}-linux-${CPU}
    mode: "0755"
    user: "root"
  "/usr/bin/helper-aws-sso-role":
    file: /root/scripts/helper-aws-sso-role
    mode: "0755"
    user: "root"
  "/etc/bash_completion.d/aws-sso-role":
    file: /root/scripts/aws-sso-role-completion.bash
    mode: "0644"
    user: "root"

EOF
    pushd /root/dist
    pkg --name=aws-sso-cli --version=$VERSION --arch=$ARCH --deb ../package.yaml
    pkg --name=aws-sso-cli --version=$VERSION --arch=$ARCH --rpm ../package.yaml
    popd
}

package amd64
package arm64
