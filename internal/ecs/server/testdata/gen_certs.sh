#!/bin/bash

cat <<-EOF > config.ssl
[dn]
CN=localhost
[req]
distinguished_name = dn
[EXT]
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EOF

openssl req -x509 -out localhost.crt -keyout localhost.key -days 3065 \
  -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config config.ssl

rm config.ssl
