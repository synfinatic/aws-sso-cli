package predictor

import "sort"

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
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

// keys match AWSRoleFlat header and value is the description
var AllListFields = map[string]string{
	"Id":            "Column Index",
	"Arn":           "AWS Role Resource Name",
	"AccountId":     "AWS AccountID (integer)",
	"AccountIdPad":  "AWS AccountID (zero padded)",
	"AccountName":   "Configured Account Name",
	"AccountAlias":  "AWS Account Alias",
	"DefaultRegion": "Default AWS Region",
	"EmailAddress":  "Root Email for AWS account",
	"Expires":       "Time until STS creds expire",
	"ExpiresEpoch":  "Unix Epoch when STS creds expire",
	"RoleName":      "AWS Role Name",
	"SSO":           "AWS SSO Instance Name",
	"Via":           "Role Chain Via",
	"Profile":       "AWS_SSO_PROFILE / AWS_PROFILE",
}

// AvailableAwsRegions lists all the AWS regions that AWS provides (aws account list-regions)
// This list is just the commercial regions, we add the other partitions using the SSO regions
// list in init()
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions
var AvailableAwsRegions []string = []string{
	"af-south-1",
	"ap-east-1",
	"ap-east-2",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-northeast-3",
	"ap-south-1",
	"ap-south-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-southeast-3",
	"ap-southeast-4",
	"ap-southeast-5",
	"ap-southeast-6",
	"ap-southeast-7",
	"ca-central-1",
	"ca-west-1",
	"eu-central-1",
	"eu-central-2",
	"eu-north-1",
	"eu-south-1",
	"eu-south-2",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"il-central-1",
	"me-central-1",
	"me-south-1",
	"mx-central-1",
	"sa-east-1",
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
}

// AWSPartition describes an AWS partition relevant to IAM Identity Center setup.
type AWSPartition struct {
	Name       string // human-readable label
	Value      string // partition identifier (e.g. "aws", "aws-cn")
	FqdnSuffix string // domain suffix for the SSO start URL hostname
	SSORegions []string
}

var AWSPartitions = []AWSPartition{
	{
		Name:       "Commercial",
		Value:      "aws",
		FqdnSuffix: ".awsapps.com",
		SSORegions: []string{
			// US
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",

			// Mexico
			"mx-central-1",

			// Africa
			"af-south-1",

			// Israel
			"il-central-1",

			// Asia Pacific
			"ap-east-1", "ap-east-2",
			"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
			"ap-south-1", "ap-south-2",
			"ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
			"ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7",

			// Canada
			"ca-central-1", "ca-west-1",

			// EU
			"eu-central-1", "eu-central-2",
			"eu-west-1", "eu-west-2", "eu-west-3",
			"eu-south-1", "eu-south-2", "eu-north-1",

			// South America
			"sa-east-1",

			// Middle East
			"me-central-1", "me-south-1",
		},
	},
	{
		Name:       "US GovCloud",
		Value:      "aws-us-gov",
		FqdnSuffix: ".signin.amazonaws-us-gov.com",
		SSORegions: []string{"us-gov-east-1", "us-gov-west-1"},
	},
	{
		Name:       "China",
		Value:      "aws-cn",
		FqdnSuffix: ".awsapps.cn",
		SSORegions: []string{"cn-north-1", "cn-northwest-1"},
	},
	// EU doesn't have global endpoints, instead they are region specific
	{
		Name:       "EU Digital Sovereignty (Brandenburg, Germany)",
		Value:      "aws-eusc",
		FqdnSuffix: ".eusc-de-east-1.portal.amazonaws.eu",
		SSORegions: []string{"eusc-de-east-1"},
	},
}

// https://docs.aws.amazon.com/general/latest/gr/sso.html
var AvailableAwsSSORegions []string = []string{}

func init() {
	for i := range AWSPartitions {
		sort.Strings(AWSPartitions[i].SSORegions)
		AvailableAwsSSORegions = append(AvailableAwsSSORegions, AWSPartitions[i].SSORegions...)

		// just include the non-commercial regions in the main list
		if i > 0 {
			AvailableAwsRegions = append(AvailableAwsRegions, AWSPartitions[i].SSORegions...)
		}
	}
}
