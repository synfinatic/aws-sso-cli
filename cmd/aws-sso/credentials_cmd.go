package main

import (
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
)

type CredentialsCmd struct {
	File    string   `kong:"short='f',help='File to write credentials to (default: stdout)',predictor='allFiles',env='AWS_SHARED_CREDENTIALS_FILE'"`
	Append  bool     `kong:"short='a',help='Append to the file instead of overwriting'"`
	Profile []string `kong:"required,short='p',name='profile',help='List of profiles to write credentials for',predictor='profile'"`
}

func (cc *CredentialsCmd) Run(ctx *RunContext) error {
	cache := ctx.Settings.Cache.GetSSO()

	creds := []awsconfig.ProfileCredentials{}

	for _, profile := range ctx.Cli.Credentials.Profile {
		roleFlat, err := cache.Roles.GetRoleByProfile(profile, ctx.Settings)
		if err != nil {
			return err
		}

		pCreds := GetRoleCredentials(ctx, AwsSSO, ctx.Cli.Console.STSRefresh, roleFlat.AccountId, roleFlat.RoleName)

		creds = append(creds, awsconfig.ProfileCredentials{
			Profile:         profile,
			AccessKeyId:     pCreds.AccessKeyId,
			SecretAccessKey: pCreds.SecretAccessKey,
			SessionToken:    pCreds.SessionToken,
			Expires:         pCreds.ExpireString(),
		})
	}

	var err error
	switch cc.File {
	case "":
		err = awsconfig.PrintProfileCredentials(creds)

	default:
		flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if cc.Append {
			flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		err = awsconfig.WriteProfileCredentials(ctx.Cli.Credentials.File, flags, creds)
	}

	return err
}
