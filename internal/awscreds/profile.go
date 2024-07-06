package awscreds

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
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Profile struct {
	// Required for import of static creds
	FromConfig      bool
	Name            string
	AccessKeyId     string `ini:"aws_access_key_id"`
	SecretAccessKey string `ini:"aws_secret_access_key"`
	MfaSerial       string `ini:"mfa_serial"`
	// optional
	/*
		Region               string `ini:"region"`
		Output               string `ini:"output"`
		CABundle             string `ini:"ca_bundle"`
		CliAutoPrompt        string `ini:"cli_auto_prompt"`
		CliBinaryFormat      string `ini:"cli_binary_format"`
		CliPager             string `ini:"cli_pager"`
		CliTimestampFormat   string `ini:"cli_timestamp_format"`
		CredentialProcess    string `ini:"credential_process"`
		CredentialSource     string `ini:"credential_source"`
		DurationSeconds      uint32 `ini:"duration_seconds"`
		ExternalId           string `ini:"external_id"`
		MaxAttempts          uint32 `ini:"max_attempts"`
		ParameterValidation  bool   `ini:"parameter_validation"`
		RetryMode            string `ini:"retry_mode"`
		RoleArn              string `ini:"role_arn"`
		RoleSessionName      string `ini:"role_session_name"`
		SourceProfile        string `ini:"source_profile"`
		SsoAccountId         int64  `ini:"sso_account_id"`
		SsoRegion            string `ini:"sso_region"`
		SsoRoleName          string `ini:"sso_role_name"`
		SsoStartUrl          string `ini:"sso_start_url"`
		StsRegionEndpoints   string `ini:"sts_region_endpoints"`
		WebIdentityTokenFile string `ini:"web_identity_token_file"`
		TcpKeepalive         bool   `ini:"tcp_keepalive"`
	*/
}

func (p *Profile) config() (aws.Config, error) {
	creds := credentials.NewStaticCredentialsProvider(
		p.AccessKeyId,
		p.SecretAccessKey,
		"", // sessionToken
	)
	return config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(creds),
	)
}

// GetArn uses the credentials to call sts:GetCallerIdentity to retrieve the ARN
func (p *Profile) GetArn() (string, error) {
	cfg, err := p.config()
	if err != nil {
		return "", err
	}

	s := sts.NewFromConfig(cfg)
	out, err := s.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}

	return aws.ToString(out.Arn), nil
}

// GetAccountAlias calls iam:ListAccountAliases to retrieve the AWS Account
// Alias.  Returns an empty string if no alias has been set.
func (p *Profile) GetAccountAlias() string {
	cfg, err := p.config()
	if err != nil {
		return ""
	}

	i := iam.NewFromConfig(cfg)
	out, err := i.ListAccountAliases(context.TODO(), &iam.ListAccountAliasesInput{})
	if err != nil {
		return ""
	}

	if len(out.AccountAliases) > 0 {
		return out.AccountAliases[0]
	}
	return ""
}
