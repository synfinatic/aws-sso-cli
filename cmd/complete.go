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
	"io/ioutil"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/posener/complete"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/utils"
)

type Predictor struct {
	configFile string
	accountids []string
	roles      []string
	arns       []string
}

// AvailableAwsRegions lists all the AWS regions that AWS provides
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions
var AvailableAwsRegions []string = []string{
	"us-gov-west-1",
	"us-gov-east-1",
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"af-south-1",
	"ap-east-1",
	"ap-south-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-northeast-3",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-south-1",
	"eu-west-3",
	"eu-north-1",
	"me-south-1",
	"sa-east-1",
}

// NewPredictor loads our cache file (if exists) and loads the values
func NewPredictor(cacheFile, configFile string) *Predictor {
	p := Predictor{
		configFile: configFile,
	}
	c, err := sso.OpenCache(cacheFile, &sso.Settings{})
	if err != nil {
		return &p
	}

	uniqueRoles := map[string]bool{}

	cache := c.GetSSO()
	for i, a := range cache.Roles.Accounts {
		id, _ := utils.AccountIdToString(i)
		p.accountids = append(p.accountids, id)
		for role, r := range a.Roles {
			p.arns = append(p.arns, r.Arn)
			uniqueRoles[role] = true
		}
	}

	for k := range uniqueRoles {
		p.roles = append(p.roles, k)
	}

	return &p
}

// FieldListComplete returns a completor for the `list` fields
func (p *Predictor) FieldListComplete() complete.Predictor {
	set := []string{}
	for f := range allListFields {
		set = append(set, f)
	}

	return complete.PredictSet(set...)
}

// AccountComplete returns a list of all the valid AWS Accounts we have in the cache
func (p *Predictor) AccountComplete() complete.Predictor {
	return complete.PredictSet(p.accountids...)
}

// RoleComplete returns a list of all the valid AWS Roles we have in the cache
func (p *Predictor) RoleComplete() complete.Predictor {
	return complete.PredictSet(p.roles...)
}

// ArnComplete returns a list of all the valid AWS Role ARNs we have in the cache
func (p *Predictor) ArnComplete() complete.Predictor {
	arns := []string{}

	// The `:` character is considered a word delimiter by bash complete
	// so we need to escape them
	for _, a := range p.arns {
		arns = append(arns, strings.ReplaceAll(a, ":", "\\:"))
	}

	return complete.PredictSet(arns...)
}

// RegionsComplete returns a list of all the valid AWS Regions
func (p *Predictor) RegionComplete() complete.Predictor {
	return complete.PredictSet(AvailableAwsRegions...)
}

// SsoComplete returns a list of the valid AWS SSO Instances
func (p *Predictor) SsoComplete() complete.Predictor {
	ssos := []string{}
	s := sso.Settings{}

	if config, err := ioutil.ReadFile(p.configFile); err == nil {
		if err = yaml.Unmarshal(config, &s); err == nil {
			for sso := range s.SSO {
				ssos = append(ssos, sso)
			}
		}
	}
	return complete.PredictSet(ssos...)
}
