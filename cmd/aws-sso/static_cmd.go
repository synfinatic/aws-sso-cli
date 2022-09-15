package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	//	"context"
	//	"errors"
	"fmt"
	"strings"

	//	"github.com/aws/aws-sdk-go-v2/aws"
	//	"github.com/aws/aws-sdk-go-v2/config"
	//	"github.com/aws/aws-sdk-go-v2/credentials"
	// "github.com/aws/aws-sdk-go-v2/service/iam"
	// "github.com/davecgh/go-spew/spew"
	//	"github.com/manifoldco/promptui"
	"github.com/manifoldco/promptui"
	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/gotable"
)

type StaticCmd struct {
	Add    StaticAddCmd `kong:"cmd,help='Manually add a static AWS API credential to the SecureStore'"`
	Delete StaticDelCmd `kong:"cmd,help='Delete a static AWS API credential from the SecureStore'"`
	//	Import StaticImportCmd `kong:"cmd,help='Import static AWS API credentials from ~/.aws/config into the SecureStore'"`
	List StaticListCmd `kong:"cmd,help='List static AWS API credentials in the SecureStore'"`
}

var currentProfiles *sso.ProfileMap

// StaticAddCmd interactively adds static credentials into the SecureStore
type StaticAddCmd struct {
	Profile     string `kong:"short='p',help='Name of the AWS Profile to create'"`
	AccessKeyId string `kong:"short='a',help='AWS AccessKeyId for the profile'"`
}

// validateAwsProfile validates our AWS_PROFILE value
func validateAwsProfile(input string) error {
	if len(input) > 0 && !strings.Contains(input, " ") {
		if currentProfiles.IsDuplicate(input) {
			return fmt.Errorf("%s is a duplicate of an existing AWS_PROFILE", input)
		}

		return nil
	}
	return fmt.Errorf("Must be a string without whitspace")
}

// validateAwsKeyId verifies the AwsAccessKeyId
func validateAwsKeyId(input string) error {
	if len(input) == 20 {
		return nil
	}
	return fmt.Errorf("AwsAccessKeyId is the wrong length")
}

// validateAwsSecretKey validates the AwsSecretAccessKey
func validateAwsSecretKey(input string) error {
	if len(input) == 40 {
		return nil
	}
	return fmt.Errorf("AwsSecretAccessKey is the wrong length")
}

func (cc *StaticAddCmd) Run(ctx *RunContext) error {
	var err error

	log.Warnf("aws-sso does not currently support MFA for static credentials.")

	// load current profiles
	currentProfiles, err = ctx.Settings.GetAllProfiles("")
	if err != nil {
		return err
	}

	profile := ctx.Cli.Static.Add.Profile
	if profile == "" {
		prompt := promptui.Prompt{
			Label:    "AWS_PROFILE",
			Validate: validateAwsProfile,
			Pointer:  promptui.PipeCursor,
		}
		if profile, err = prompt.Run(); err != nil {
			return err
		}
	}

	accessKey := ctx.Cli.Static.Add.AccessKeyId
	if accessKey == "" {
		prompt := promptui.Prompt{
			Label:    "AwsAccessKeyId",
			Validate: validateAwsKeyId,
			Pointer:  promptui.PipeCursor,
		}
		accessKey, err = prompt.Run()
		if err != nil {
			return err
		}
	}

	prompt := promptui.Prompt{
		Label:    "AwsSecretAccessKey",
		Validate: validateAwsSecretKey,
		Mask:     '*',
		Pointer:  promptui.PipeCursor,
	}
	secretKey, err := prompt.Run()
	if err != nil {
		return err
	}

	// check if key is valid
	p := awsconfig.Profile{
		FromConfig:      false,
		Name:            profile,
		AccessKeyId:     accessKey,
		SecretAccessKey: secretKey,
		MfaSerial:       "",
	}

	arn, err := p.GetArn()
	if err != nil {
		return fmt.Errorf("Unable to validate credentials: %s", err.Error())
	}

	accountId, userName, _ := utils.ParseUserARN(arn)

	err = ctx.Store.SaveStaticCredentials(arn, storage.StaticCredentials{
		Profile:         profile,
		UserName:        userName,
		AccountId:       accountId,
		AccessKeyId:     accessKey,
		SecretAccessKey: secretKey,
		Tags:            map[string]string{},
	})
	if err != nil {
		return err
	}

	log.Infof("Added static API credentials: %s = %s", profile, arn)

	return nil
}

// StaticDelCmd deletes static credentials from the SecureStore
type StaticDelCmd struct {
	Profile string `kong:"short='p',required,help='Name of the AWS Profile to delete'"`
}

func (cc *StaticDelCmd) Run(ctx *RunContext) error {
	arns := ctx.Store.ListStaticCredentials()
	creds := storage.StaticCredentials{}
	found := false
	arn := ""
	for _, arn = range arns {
		if err := ctx.Store.GetStaticCredentials(arn, &creds); err != nil {
			return err
		}
		if creds.Profile == ctx.Cli.Static.Delete.Profile {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("Unable to find %s in SecureStore", ctx.Cli.Static.Delete.Profile)
	}

	if err := ctx.Store.DeleteStaticCredentials(arn); err != nil {
		return err
	}

	log.Infof("Deleted static API credentials: %s = %s",
		ctx.Cli.Static.Delete.Profile, creds.UserArn())

	return nil
}

// List Credentials
type StaticListCmd struct{}

// StaticListCmd lists all of the static credentials stored in the SecureStore
func (cc *StaticListCmd) Run(ctx *RunContext) error {
	arns := ctx.Store.ListStaticCredentials()

	// no report
	if len(arns) == 0 {
		fmt.Printf("No static credentials are held in the SecureStore.")
		return nil
	}

	screds := make([]gotable.TableStruct, len(arns))

	for i, arn := range arns {
		staticCreds := storage.StaticCredentials{}
		if err := ctx.Store.GetStaticCredentials(arn, &staticCreds); err != nil {
			log.WithError(err).Warnf("Unable to retrieve static creds for %s", arn)
			continue
		}
		screds[i] = staticCreds
	}

	fields := []string{"Profile", "AccountId", "UserName"}
	if err := gotable.GenerateTable(screds, fields); err != nil {
		log.WithError(err).Fatalf("Unable to generate report")
	}
	fmt.Printf("\n")

	return nil
}

/*
// Import Credentials
type StaticImportCmd struct{}

// StaticImportCmd imports static credentials into the SecureStore
func (cc *StaticImportCmd) Run(ctx *RunContext) error {
	a, err := awsconfig.NewAwsConfig(awsconfig.CONFIG_FILE, awsconfig.CREDENTIALS_FILE)
	if err != nil {
		return err
	}

	p, err := a.StaticProfiles()
	if err != nil {
		return err
	}
	fmt.Printf("Profiles:\n%s", spew.Sdump(p))

	return nil
}
*/
