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
	"github.com/synfinatic/aws-sso-cli/sso"
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
	Config *sso.ConfigFile // whole config file
	Store  sso.SecureStorage
	Cache  *sso.Cache
}

const (
	CONFIG_DIR          = "~/.aws-sso"
	CONFIG_FILE         = CONFIG_DIR + "/config.yaml"
	JSON_STORE_FILE     = CONFIG_DIR + "/store.json"
	INSECURE_CACHE_FILE = CONFIG_DIR + "/cache.json"
	DEFAULT_STORE       = "file"
)

type CLI struct {
	// Common Arguments
	LogLevel   string `kong:"optional,short='L',name='level',default='info',enum='error,warn,info,debug',help='Logging level [error|warn|info|debug]'"`
	Lines      bool   `kong:"optional,help='Print line number in logs'"`
	ConfigFile string `kong:"optional,name='config',default='${CONFIG_FILE}',help='Config file',env='AWS_SSO_CONFIG'"`
	Browser    string `kong:"optional,short='b',help='Path to browser to use',env='AWS_SSO_BROWSER'"`
	PrintUrl   bool   `kong:"optional,name='url',short='u',help='Print URL insetad of open in browser'"`
	SSO        string `kong:"optional,short='S',help='AWS SSO Instance',env='AWS_SSO'"`

	// Commands
	Console ConsoleCmd `kong:"cmd,help='Open AWS Console using specificed AWS Role/profile'"`
	Exec    ExecCmd    `kong:"cmd,help='Execute command using specified AWS Role/Profile'"`
	Flush   FlushCmd   `kong:"cmd,help='Force delete of AWS SSO credentials'"`
	List    ListCmd    `kong:"cmd,help='List all accounts / role (default command)',default='1'"`
	Tags    TagsCmd    `kong:"cmd,help='List tags'"`
	Time    TimeCmd    `kong:"cmd,help='Print out much time before STS Token expires'"`
	Version VersionCmd `kong:"cmd,help='Print version and exit'"`
}

func main() {
	cli := CLI{}
	ctx := parse_args(&cli)

	run_ctx := RunContext{
		Kctx:   ctx,
		Cli:    &cli,
		Konf:   koanf.New("."),
		Config: &sso.ConfigFile{},
	}

	// Load the config file
	config := getHomePath(cli.ConfigFile)
	if err := run_ctx.Konf.Load(file.Provider(config), yaml.Parser()); err != nil {
		log.WithError(err).Fatalf("Unable to open config file: %s", config)
	}
	err := run_ctx.Konf.Unmarshal("", run_ctx.Config)
	if err != nil {
		log.WithError(err).Fatalf("Unable to process config file")
	}
	update_config(run_ctx.Config, cli)

	// validate the SSO Provider
	if run_ctx.Cli.SSO != "" {
		var ok bool
		_, ok = run_ctx.Config.SSO[run_ctx.Cli.SSO]
		if !ok {
			names := []string{}
			for sso, _ := range run_ctx.Config.SSO {
				names = append(names, sso)
			}
			log.Fatalf("Invalid SSO name: %s.  Valid options: %s", run_ctx.Cli.SSO, strings.Join(names, ", "))
		}
	} else if len(run_ctx.Config.SSO) == 1 {
		for name, _ := range run_ctx.Config.SSO {
			run_ctx.Cli.SSO = name
		}
	} else {
		log.Fatalf("Please specify --sso, $AWS_SSO or set DefaultSSO in the config file")
	}

	// Load the insecure cache
	cfile := getHomePath(INSECURE_CACHE_FILE)
	if run_ctx.Config.CacheStore != "" {
		cfile = getHomePath(run_ctx.Config.CacheStore)
	}
	run_ctx.Cache, err = sso.OpenCache(cfile)
	if err != nil {
		log.WithError(err).Fatalf("Unable to open cache %s", cfile)
	}

	// Load the secure store data
	switch run_ctx.Config.SecureStore {
	case "json":
		sfile := getHomePath(JSON_STORE_FILE)
		if run_ctx.Config.JsonStore != "" {
			sfile = getHomePath(run_ctx.Config.JsonStore)
		}
		run_ctx.Store, err = sso.OpenJsonStore(sfile)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open JsonStore %s", sfile)
		}
	default:
		cfg := sso.NewKeyringConfig(run_ctx.Config.SecureStore, CONFIG_DIR)
		run_ctx.Store, err = sso.OpenKeyring(cfg)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open SecureStore %s", run_ctx.Config.SecureStore)
		}
	}

	err = ctx.Run(&run_ctx)
	if err != nil {
		log.Fatalf("Error running command: %s", err.Error())
	}
}

// Some CLI args are for overriding the config.  Do that here.
func update_config(config *sso.ConfigFile, cli CLI) {
	if cli.PrintUrl {
		config.PrintUrl = true
	}
	if cli.Browser != "" {
		config.Browser = cli.Browser
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
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       true,
	})

	return ctx
}

type VersionCmd struct{} // takes no arguments

func (cc *VersionCmd) Run(ctx *RunContext) error {
	delta := ""
	if len(Delta) > 0 {
		delta = fmt.Sprintf(" [%s delta]", Delta)
		Tag = "Unknown"
	}
	fmt.Printf("AWS SSO CLI Version %s -- Copyright 2021 Aaron Turner\n", Version)
	fmt.Printf("%s (%s)%s built at %s\n", CommitID, Tag, delta, Buildinfos)
	return nil
}

func getHomePath(path string) string {
	return strings.Replace(path, "~", os.Getenv("HOME"), 1)
}
