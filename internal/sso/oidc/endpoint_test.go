package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizationEndpoint(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		// commercial partition lives under amazonaws.com
		"us-east-1": "https://oidc.us-east-1.amazonaws.com/authorize",
		"eu-west-1": "https://oidc.eu-west-1.amazonaws.com/authorize",
		// AWS European Sovereign Cloud lives under amazonaws.eu, not amazonaws.com
		"eusc-de-east-1": "https://oidc.eusc-de-east-1.amazonaws.eu/authorize",
		// China lives under amazonaws.com.cn
		"cn-north-1": "https://oidc.cn-north-1.amazonaws.com.cn/authorize",
		// GovCloud lives under amazonaws.com
		"us-gov-east-1": "https://oidc.us-gov-east-1.amazonaws.com/authorize",
	}

	for region, expected := range tests {
		assert.Equal(t, expected, AuthorizationEndpoint(region), "region %q", region)
	}
}
