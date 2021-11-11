#!/usr/bin/env bash

: ${VERSION?}

function package() {
    local CPU=$1
    cat <<EOF >/root/package.yaml
meta:
  description: AWS SSO CLI
  vendor: Aaron Turner
  maintainer: Aaron Turner
files:
  "/usr/bin/aws-sso":
    file: /root/dist/aws-sso-${VERSION}-linux-${CPU}
    mode: "0755"
    user: "root"

EOF
}

package amd64

pushd /root/dist
pkg --name=aws-sso-cli --version=$VERSION --arch=x86_64 --deb ../package.yaml
pkg --name=aws-sso-cli --version=$VERSION --arch=x86_64 --rpm ../package.yaml
pkg --name=aws-sso-cli --version=$VERSION --arch=arm64 --deb ../package.yaml
pkg --name=aws-sso-cli --version=$VERSION --arch=arm64 --rpm ../package.yaml
popd
