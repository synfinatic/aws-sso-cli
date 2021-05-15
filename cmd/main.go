package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <aturner at synfin dot net>
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

	"github.com/alecthomas/kong"
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
	Config *ConfigFile
}

type CLI struct {
	// Common Arguments
	LogLevel string `kong:"optional,short='L',name='loglevel',default='info',enum='error,warn,info,debug',help='Logging level [error|warn|info|debug]'"`
	Lines    bool   `kong:"optional,name='lines',help='Print line number in logs'"`
	Browser  string `kong:"optional,name='browser',short='b',help='Path to browser to use',env='AWS_SSO_BROWSER'"`
	// have to hard code CONFIG_YAML value here because no way to do string interpolation in a strcture tag.
	ConfigFile string `kong:"optional,short='c',name='config',default='~/.aws-sso/config.yaml',help='Config file'"`
	// AWS Params
	Region   string `kong:"optional,short='r',help='AWS Region',env='AWS_DEFAULT_REGION'"`
	Duration int64  `kong:"optional,short='d',help='AWS Session duration in minutes (default 60)',default=60,env=AWS_SSO_DURATION"`

	// Commands
	//	Exec    ExecCmd    `kong:"cmd,help='Execute command using specified AWS Role/Profile'"`
	List ListCmd `kong:"cmd,help='List all accounts / role (default command)',default='1'"`
	//	Expire  ExpireCmd  `kong:"cmd,help='Force expire of AWS Role/Profile credentials from keychain'"`
	Version VersionCmd `kong:"cmd,help='Print version and exit'"`
}

func main() {
	cli := CLI{}
	ctx := parse_args(&cli)

	c, err := LoadConfigFile(GetPath(cli.ConfigFile))
	if err != nil {
		log.Fatalf("Unable to load config: %s", err.Error())
	}

	run_ctx := RunContext{
		Kctx:   ctx,
		Cli:    &cli,
		Config: c,
	}
	err = ctx.Run(&run_ctx)
	if err != nil {
		log.Fatalf("Error running command: %s", err.Error())
	}
}

func parse_args(cli *CLI) *kong.Context {
	op := kong.Description("Utility to manage temporary AWS API Credentials issued via AWS SSO")
	ctx := kong.Parse(cli, op)

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
