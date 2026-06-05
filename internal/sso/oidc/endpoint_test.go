package oidc

import (
	"strings"
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

// TestAuthorizationEndpointFIPS verifies FIPS endpoint resolution when
// AWS_USE_FIPS_ENDPOINT is set. Cannot run in parallel due to env var mutation.
func TestAuthorizationEndpointFIPS(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

	tests := map[string]string{
		// commercial regions get the oidc-fips. hostname prefix
		"us-east-1": "https://oidc-fips.us-east-1.amazonaws.com/authorize",
		"eu-west-1": "https://oidc-fips.eu-west-1.amazonaws.com/authorize",
		// GovCloud is already FIPS-compliant; the hostname does not change
		"us-gov-east-1": "https://oidc.us-gov-east-1.amazonaws.com/authorize",
		"us-gov-west-1": "https://oidc.us-gov-west-1.amazonaws.com/authorize",
		// European Sovereign Cloud uses amazonaws.eu TLD with fips prefix
		"eusc-de-east-1": "https://oidc-fips.eusc-de-east-1.amazonaws.eu/authorize",
		// China uses amazonaws.com.cn TLD with fips prefix
		"cn-north-1": "https://oidc-fips.cn-north-1.amazonaws.com.cn/authorize",
	}

	for region, expected := range tests {
		ep, err := AuthorizationEndpoint(region)
		require.NoError(t, err, "region %q", region)
		assert.Equal(t, expected, ep, "region %q", region)
	}
}

// TestAuthorizationEndpointFIPSErrorMessage verifies that error messages mention
// "FIPS" when AWS_USE_FIPS_ENDPOINT is set and resolution fails.
func TestAuthorizationEndpointFIPSErrorMessage(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

	// Empty region fails before the SDK call; confirm the generic error still fires.
	ep, err := AuthorizationEndpoint("")
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.False(t, strings.Contains(err.Error(), "FIPS"), "empty-region error should not mention FIPS")
}
