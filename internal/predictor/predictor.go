package predictor

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
	"strings"

	// "github.com/davecgh/go-spew/spew"
	"github.com/goccy/go-yaml"
	"github.com/posener/complete"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/flexlog"
)

var log flexlog.FlexLogger

func init() {
	log = logger.GetLogger()
}

type Predictor struct {
	configFile string
	accountids []string
	arns       []string
	roles      []string
	profiles   []string
}

// NewPredictor loads our cache file (if exists) and loads the values
func NewPredictor(cacheFile, configFile string) *Predictor {
	defaults := map[string]interface{}{}

	// select our SSO from a CLI flag or env var, else use our default
	override := sso.OverrideSettings{
		DefaultSSO: getSSOValue(),
		LogLevel:   "warn",
	}

	p := Predictor{
		configFile: configFile,
	}

	settings, err := sso.LoadSettings(configFile, cacheFile, defaults, override)
	if err != nil {
		return &p
	}

	c, err := sso.OpenCache(cacheFile, settings)
	if err != nil {
		return &p
	}

	return p.newPredictor(settings, c)
}

// newPredictor returns a Predictor based on our settings & cache structs
func (p *Predictor) newPredictor(s *sso.Settings, c *sso.Cache) *Predictor {
	uniqueRoles := map[string]bool{}

	cache := c.GetSSO()

	// read our CLI to filter based on account and/or role
	filterAccount := getAccountIdFlag()
	filterRole := getRoleFlag()

	for aid := range cache.Roles.Accounts {
		if filterAccount > 0 && filterAccount != aid {
			continue
		}
		id, _ := utils.AccountIdToString(aid)

		addedRole := false
		for roleName, rFlat := range cache.Roles.GetAccountRoles(aid) {
			if filterRole != "" && filterRole != roleName {
				continue
			}
			addedRole = true

			p.arns = append(p.arns, rFlat.Arn)
			uniqueRoles[roleName] = true
			profile, err := rFlat.ProfileName(s)
			if err != nil {
				log.Warn("unable to find Profile for ARN", "arn", rFlat.Arn, "error", err.Error())
				continue
			}
			p.profiles = append(p.profiles, profile)
		}

		// only include our AccountId if we actually added a role from it
		if addedRole {
			p.accountids = append(p.accountids, id)
		}
	}

	for k := range uniqueRoles {
		p.roles = append(p.roles, k)
	}

	return p
}

// FieldListComplete returns a completor for the `list` fields
func (p *Predictor) FieldListComplete() complete.Predictor {
	set := []string{}
	for f := range AllListFields {
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

	if config, err := os.ReadFile(p.configFile); err == nil {
		if err = yaml.Unmarshal(config, &s); err == nil {
			for sso := range s.SSO {
				ssos = append(ssos, sso)
			}
		} else {
			log.Fatal("unable to process file", "file", p.configFile, "error", err.Error())
		}
	}
	return complete.PredictSet(ssos...)
}

// ProfileComplete returns a list of all the valid AWS_PROFILE values
func (p *Predictor) ProfileComplete() complete.Predictor {
	profiles := []string{}

	// The `:` character is considered a word delimiter by bash complete
	// so we need to escape them
	for _, x := range p.profiles {
		if os.Getenv("__NO_ESCAPE_COLONS") == "" {
			profiles = append(profiles, strings.ReplaceAll(x, ":", "\\:"))
		} else {
			// fish doesn't treat colons as word delimiters
			profiles = append(profiles, x)
		}
	}

	return complete.PredictSet(profiles...)
}

// getSSOValue scans our os.Args and returns our SSO if specified,
// or fails to the AWS_SSO env var
func getSSOValue() string {
	sso := ""
	args := os.Args[1:]
	for i, v := range args {
		if v == "-S" || v == "--sso" {
			if i+1 < len(args) {
				sso = args[i+1]
			}
		}
	}
	if sso == "" {
		sso = getSSOFlag()
	}
	if sso == "" {
		sso = os.Getenv("AWS_SSO")
	}
	return sso
}

func SupportedListField(name string) bool {
	ret := false
	for k := range AllListFields {
		if k == name {
			ret = true
			break
		}
	}
	return ret
}
