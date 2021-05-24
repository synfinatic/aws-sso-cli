package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	log "github.com/sirupsen/logrus"
)

// These variables are defined in the Makefile
var Version = "unknown"
var Buildinfos = "unknown"
var Tag = "NO-TAG"
var CommitID = "unknown"
var Delta = ""

type RunContext struct {
	Kctx   *kong.Context
	Cli    *CLI
	Konf   *koanf.Koanf
	Config *SSOConfig
}

const (
	CONFIG_DIR            = "~/.aws-sso"
	CONFIG_FILE           = CONFIG_DIR + "/config.yaml"
	JSON_STORE_FILE       = CONFIG_DIR + "/store.json"
	ENV_SSO_FILE_PASSWORD = "AWS_SSO_FILE_PASSPHRASE"
	ENV_SSO_REGION        = "AWS_SSO_DEFAULT_REGION"
	DEFAULT_STORE         = "json" // XXX: FIXME
)

type CLI struct {
	// Common Arguments
	LogLevel   string `kong:"optional,short='L',name='loglevel',default='info',enum='error,warn,info,debug',help='Logging level [error|warn|info|debug]'"`
	Lines      bool   `kong:"optional,name='lines',help='Print line number in logs'"`
	Browser    string `kong:"optional,name='browser',short='b',help='Path to browser to use',env='AWS_SSO_BROWSER'"`
	PrintUrl   bool   `kong:"optional,name='url',short='u',help='Print URL insetad of open in browser'"`
	ConfigFile string `kong:"optional,name='config',short='c',default='${CONFIG_FILE}',help='Config file',env='AWS_SSO_CONFIG'"`
	// AWS Params
	Region   string `kong:"optional,name='region',short='r',help='AWS Region',env='AWS_DEFAULT_REGION'"`
	Duration int64  `kong:"optional,name='duration',short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`

	// Store
	Store     string `kong:"optional,name='store',short='s',default='${DEFAULT_STORE}',enum='json,keyring',help='Data secure store'"`
	JsonStore string `kong:"optional,name='json-store',short='j',default='${JSON_STORE_FILE}',help='Path to JSON store file'"`

	// Commands
	//	Exec    ExecCmd    `kong:"cmd,help='Execute command using specified AWS Role/Profile'"`
	List    ListCmd    `kong:"cmd,help='List all accounts / role (default command)',default='1'"`
	Expire  ExpireCmd  `kong:"cmd,help='Force expire of AWS OIDC credentials'"`
	Version VersionCmd `kong:"cmd,help='Print version and exit'"`
}

func main() {
	cli := CLI{}
	ctx := parse_args(&cli)

	run_ctx := RunContext{
		Kctx:   ctx,
		Cli:    &cli,
		Konf:   koanf.New("."),
		Config: &SSOConfig{},
	}

	config := GetPath(cli.ConfigFile)
	if err := run_ctx.Konf.Load(file.Provider(config), yaml.Parser()); err != nil {
		log.WithError(err).Fatalf("Unable to open config file: %s", config)
	}
	err := run_ctx.Konf.Unmarshal("", run_ctx.Config)
	if err != nil {
		log.WithError(err).Fatalf("Unable to process config file")
	}

	err = ctx.Run(&run_ctx)
	if err != nil {
		log.Fatalf("Error running command: %s", err.Error())
	}
}

func parse_args(cli *CLI) *kong.Context {
	op := kong.Description("Securely manage temporary AWS API Credentials issued via AWS SSO")
	// need to pass in the variables for defaults
	vars := kong.Vars{
		"CONFIG_DIR":      CONFIG_DIR,
		"CONFIG_FILE":     CONFIG_FILE,
		"DEFAULT_STORE":   DEFAULT_STORE,
		"JSON_STORE_FILE": JSON_STORE_FILE,
	}
	ctx := kong.Parse(cli, op, vars)

	switch cli.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}

	if cli.Lines {
		log.SetReportCaller(true)
	}

	return ctx
}

type VersionCmd struct{}

func (cc *VersionCmd) Run(ctx *RunContext) error {
	delta := ""
	if len(Delta) > 0 {
		delta = fmt.Sprintf(" [%s delta]", Delta)
		Tag = "Unknown"
	}
	fmt.Printf("AWS SSO Version %s -- Copyright 2021 Aaron Turner\n", Version)
	fmt.Printf("%s (%s)%s built at %s\n", CommitID, Tag, delta, Buildinfos)
	return nil
}

func GetPath(path string) string {
	return strings.Replace(path, "~", os.Getenv("HOME"), 1)
}
