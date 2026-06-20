package awsendpoint

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

import (
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func UseFipsEndpoint() bool {
	var err error
	useFips := false
	if v, ok := os.LookupEnv("AWS_USE_FIPS_ENDPOINT"); ok {
		useFips, err = strconv.ParseBool(v)
		if err != nil {
			log.Warn("Invalid value for AWS_USE_FIPS_ENDPOINT; defaulting to false", "value", v)
			useFips = false
		}
	}
	return useFips
}

func FipsEndpointState() aws.FIPSEndpointState {
	if UseFipsEndpoint() {
		return aws.FIPSEndpointStateEnabled
	}
	return aws.FIPSEndpointStateDisabled
}

func UseDualStackEndpoint() bool {
	var err error
	useDualStack := false
	if v, ok := os.LookupEnv("AWS_USE_DUALSTACK_ENDPOINT"); ok {
		useDualStack, err = strconv.ParseBool(v)
		if err != nil {
			log.Warn("Invalid value for AWS_USE_DUALSTACK_ENDPOINT; defaulting to false", "value", v)
			useDualStack = false
		}
	}
	return useDualStack
}

func DualStackEndpointState() aws.DualStackEndpointState {
	if UseDualStackEndpoint() {
		return aws.DualStackEndpointStateEnabled
	}
	return aws.DualStackEndpointStateDisabled
}
