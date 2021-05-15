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
	//	"encoding/json"
	//	"fmt"
	/*
		"github.com/aws/aws-sdk-go/aws/client"
		"github.com/aws/aws-sdk-go/aws/awserr"
		"github.com/aws/aws-sdk-go/aws/credentials"
		"github.com/aws/aws-sdk-go/service/sso"
		"github.com/aws/aws-sdk-go/service/sts"
		"github.com/skratchdot/open-golang/open" // default opener
	*/
	//	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssooidc"
)

const (
	awsSSOClientName = "aws-sso-go"
	awsSSOClientTYpe = "public"
	awsSSOGrantType  = "urn:ietf:params:oauth:grant-type:device_code"
)

// this struct should be cached for long term if possible
type RegisterClientResponse struct {
	ClientId          string `json:"clientid"`
	ClientSecret      string `json:"clientSecret"`
	ClientIdIssuedAt  uint64 `json:"clientIdIssuedAt"`
	ClientIdExpiresAt uint64 `json:"clientIdExpiresAt"`
}

type StartDeviceAuthResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationUri         string `json:"verificationUri"`
	VerificationUriComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

type CreateTokenResponse struct {
	AccessToken string `json:"accessToken"` // should be cached to issue new creds
	TokenType   string `json:"tokenType"`
	ExpiresIn   int    `json:"expiresIn"`
}

type RoleCredentialsResponse struct {
	Credentials RoleCredentials `json:"roleCredentials"`
}

type RoleCredentials struct { // Cache
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      uint64 `json:"expiration"`
}

func RegisterClient(clientName, clientType, ssoRegion string) (*ssooidc.RegisterClientOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := ssooidc.New(mySession, aws.NewConfig().WithRegion("us-east-1"))
	input := ssooidc.RegisterClientInput{
		ClientName: aws.String(clientName),
		ClientType: aws.String(clientType),
		Scopes:     nil,
	}
	return svc.RegisterClient(&input)
}
