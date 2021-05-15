module github.com/synfinatic/aws-sso-cli

go 1.16

// pin this version (or later) until 99designs/keyring updates.
replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4

require (
	github.com/alecthomas/kong v0.2.15
	github.com/goccy/go-yaml v1.8.4
	github.com/sirupsen/logrus v1.7.0
	github.com/synfinatic/onelogin-aws-role v0.1.4
	github.com/aws/aws-sdk-go v1.38.40
	github.com/99designs/keyring v1.1.6
)
