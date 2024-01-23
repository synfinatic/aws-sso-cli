package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"

	"github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
)

type SetupCmd struct {
	All       SetupAllCmd  `kong:"cmd,default,help='Run full initial setup (default)'"`
	Wizard    WizardCmd    `kong:"cmd,help='Run configuration wizard'"`
	Shell     ShellCmd     `kong:"cmd,help='Manage shell completions'"`
	AwsConfig AwsConfigCmd `kong:"cmd,help='Manage AWS SSO [profile] in ~/.aws/config'"`
}

type SetupAllCmd struct {
	Advanced bool `kong:"help='Enable advanced wizard configuration'"`
}

func (cc *SetupAllCmd) Run(ctx *RunContext) error {
	var err error

	wizard := WizardCmd{}
	ctx.Cli.Setup.Wizard.Advanced = ctx.Cli.Setup.All.Advanced
	if err = wizard.Run(ctx); err != nil {
		log.WithError(err).Fatalf("Wizard failure")
	}

	// reload our config
	cacheFile := utils.GetHomePath(INSECURE_CACHE_FILE)
	if ctx.Settings, err = sso.LoadSettings(ctx.Cli.ConfigFile, cacheFile, DEFAULT_CONFIG, ctx.Override); err != nil {
		log.WithError(err).Fatalf("load settings")
	}

	// override logging because our default config is very limited
	log.SetLevel(logrus.InfoLevel)

	// load the secure store
	loadSecureStore(ctx)

	// Force an auth to AWS
	log.Info("Will now authenticate to AWS...")
	doAuth(ctx)

	log.Info("Updating shell scripts...")
	shell := ShellCmd{}
	ctx.Cli.Setup.Shell.Install = true
	if err = shell.Run(ctx); err != nil {
		log.WithError(err).Fatalf("Shell failure")
	}

	cfgFile := "~/.aws/config"
	if cfg, ok := os.LookupEnv("AWS_CONFIG_FILE"); ok {
		cfgFile = cfg
	}
	log.Infof("Updating %s...", cfgFile)

	awsConfig := AwsConfigCmd{}
	ctx.Cli.Setup.AwsConfig.Diff = true
	return awsConfig.Run(ctx)
}
