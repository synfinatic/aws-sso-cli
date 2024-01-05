module github.com/synfinatic/aws-sso-cli

go 1.21

require (
	github.com/99designs/keyring v1.2.2
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/alecthomas/kong v0.8.1
	github.com/atotto/clipboard v0.1.4
	github.com/c-bata/go-prompt v0.2.5 // 0.2.6 is broken
	github.com/davecgh/go-spew v1.1.1
	github.com/goccy/go-yaml v1.11.2
	github.com/hexops/gotextdiff v1.0.3
	github.com/knadh/koanf v1.5.0
	github.com/manifoldco/promptui v0.9.0
	github.com/posener/complete v1.2.3
	github.com/sirupsen/logrus v1.9.3
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/stretchr/testify v1.8.4
	github.com/synfinatic/gotable v0.0.3
	github.com/willabides/kongplete v0.2.0
	golang.org/x/crypto v0.17.0 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2 v1.24.1
	github.com/riywo/loginshell v0.0.0-20200815045211-7d26008be1ab
	golang.org/x/term v0.15.0
	gopkg.in/ini.v1 v1.67.0
)

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dvsekhvalnov/jose2go v1.6.0 // indirect
	github.com/fatih/color v1.10.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-tty v0.0.3 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/pkg/term v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect

	// see: https://github.com/sirupsen/logrus/issues/1275
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect

	// see: https://github.com/go-yaml/yaml/issues/666
	// imported via testify, but they haven't yet merged the PR
	// with the fix yet
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/config v1.19.1
	github.com/aws/aws-sdk-go-v2/credentials v1.13.43
	github.com/aws/aws-sdk-go-v2/service/iam v1.24.0
	github.com/aws/aws-sdk-go-v2/service/sso v1.18.6
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.17.3
	github.com/aws/aws-sdk-go-v2/service/sts v1.23.2
	golang.org/x/net v0.19.0
)

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.45 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.37 // indirect
	github.com/aws/smithy-go v1.19.0 // indirect
)
