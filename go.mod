module github.com/synfinatic/aws-sso-cli

go 1.22

toolchain go1.22.5

require (
	github.com/99designs/keyring v1.2.2
	github.com/Masterminds/sprig/v3 v3.3.0
	github.com/alecthomas/kong v1.2.1
	github.com/atotto/clipboard v0.1.4
	github.com/c-bata/go-prompt v0.2.5 // 0.2.6 is broken
	github.com/davecgh/go-spew v1.1.1
	github.com/goccy/go-yaml v1.12.0
	github.com/hexops/gotextdiff v1.0.3
	github.com/knadh/koanf v1.5.0
	github.com/manifoldco/promptui v0.9.0
	github.com/posener/complete v1.2.3
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/stretchr/testify v1.9.0
	github.com/synfinatic/flexlog v0.0.5
	github.com/synfinatic/gotable v0.0.3
	github.com/willabides/kongplete v0.2.0
	golang.org/x/crypto v0.27.0 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2 v1.32.1
	github.com/riywo/loginshell v0.0.0-20200815045211-7d26008be1ab
	golang.org/x/term v0.24.0
)

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.3.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dvsekhvalnov/jose2go v1.6.0 // indirect
	github.com/fatih/color v1.17.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-tty v0.0.3 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/pkg/term v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect

	// see: https://github.com/sirupsen/logrus/issues/1275
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect

	// see: https://github.com/go-yaml/yaml/issues/666
	// imported via testify, but they haven't yet merged the PR
	// with the fix yet
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/MakeNowJust/heredoc v1.0.0
	github.com/aws/aws-sdk-go-v2/config v1.27.24
	github.com/aws/aws-sdk-go-v2/credentials v1.17.24
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.1
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.1
	github.com/docker/docker v27.2.1+incompatible
	github.com/docker/go-connections v0.5.0
	golang.org/x/net v0.29.0
)

require (
	dario.cat/mergo v1.0.1 // indirect
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.15 // indirect
	github.com/aws/smithy-go v1.22.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-json-experiment/json v0.0.0-20240815174924-0599f16bf0e2 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/lmittmann/tint v1.0.5 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/veqryn/slog-json v0.3.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/otel v1.28.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.28.0 // indirect
	go.opentelemetry.io/otel/metric v1.28.0 // indirect
	go.opentelemetry.io/otel/sdk v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.28.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	gotest.tools/v3 v3.5.1 // indirect
)
