package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		ep, err := AuthorizationEndpoint(region)
		require.NoError(t, err, "region %q", region)
		assert.Equal(t, expected, ep, "region %q", region)
	}
}

func TestAuthorizationEndpointEmptyRegion(t *testing.T) {
	t.Parallel()

	ep, err := AuthorizationEndpoint("")
	assert.Error(t, err)
	assert.Empty(t, ep)
}
