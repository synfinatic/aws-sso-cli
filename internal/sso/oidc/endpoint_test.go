package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
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

// TestAuthorizationEndpointFIPSEmptyRegion verifies that the empty-region guard
// fires before the SDK resolver is consulted, so the error never mentions FIPS
// even when AWS_USE_FIPS_ENDPOINT is set.
func TestAuthorizationEndpointFIPSEmptyRegion(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

	ep, err := AuthorizationEndpoint("")
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.False(t, strings.Contains(err.Error(), "FIPS"), "empty-region error should not mention FIPS")
}

// TestAuthorizationEndpointFIPSResolverError verifies that when the SDK resolver
// fails with FIPS enabled the error message contains "FIPS".
func TestAuthorizationEndpointFIPSResolverError(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

	ep, err := authorizationEndpoint("us-east-1", &errResolver{})
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.True(t, strings.Contains(err.Error(), "FIPS"), "resolver error should mention FIPS")
	assert.False(t, strings.Contains(err.Error(), "dual-stack"), "FIPS-only error should not mention dual-stack")
}

// TestAuthorizationEndpointDualStack verifies dual-stack endpoint resolution when
// AWS_USE_DUALSTACK_ENDPOINT is set. Cannot run in parallel due to env var mutation.
func TestAuthorizationEndpointDualStack(t *testing.T) {
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")

	tests := map[string]string{
		// commercial partition dual-stack uses api.aws TLD
		"us-east-1": "https://oidc.us-east-1.api.aws/authorize",
		"eu-west-1": "https://oidc.eu-west-1.api.aws/authorize",
		// GovCloud dual-stack also uses api.aws
		"us-gov-east-1": "https://oidc.us-gov-east-1.api.aws/authorize",
		// European Sovereign Cloud dual-stack uses api.amazonwebservices.eu
		"eusc-de-east-1": "https://oidc.eusc-de-east-1.api.amazonwebservices.eu/authorize",
		// China dual-stack uses api.amazonwebservices.com.cn
		"cn-north-1": "https://oidc.cn-north-1.api.amazonwebservices.com.cn/authorize",
	}

	for region, expected := range tests {
		ep, err := AuthorizationEndpoint(region)
		require.NoError(t, err, "region %q", region)
		assert.Equal(t, expected, ep, "region %q", region)
	}
}

// TestAuthorizationEndpointDualStackEmptyRegion verifies that the empty-region
// guard fires before the SDK resolver is consulted, so the error never mentions
// dual-stack even when AWS_USE_DUALSTACK_ENDPOINT is set.
func TestAuthorizationEndpointDualStackEmptyRegion(t *testing.T) {
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")

	ep, err := AuthorizationEndpoint("")
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.False(t, strings.Contains(err.Error(), "dual-stack"),
		"empty-region error must not mention dual-stack (fires before resolver)")
}

// TestAuthorizationEndpointDualStackResolverError verifies that when the SDK
// resolver fails with dual-stack enabled the error message contains "dual-stack".
func TestAuthorizationEndpointDualStackResolverError(t *testing.T) {
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")

	ep, err := authorizationEndpoint("us-east-1", &errResolver{})
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.True(t, strings.Contains(err.Error(), "dual-stack"), "resolver error should mention dual-stack")
	assert.False(t, strings.Contains(err.Error(), "FIPS"), "dual-stack-only error should not mention FIPS")
}

// TestAuthorizationEndpointFIPSDualStack verifies that setting both
// AWS_USE_FIPS_ENDPOINT and AWS_USE_DUALSTACK_ENDPOINT resolves the combined
// FIPS+dual-stack endpoint (oidc-fips.{region}.api.aws for commercial regions).
func TestAuthorizationEndpointFIPSDualStack(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")

	tests := map[string]string{
		"us-east-1":      "https://oidc-fips.us-east-1.api.aws/authorize",
		"us-gov-east-1":  "https://oidc-fips.us-gov-east-1.api.aws/authorize",
		"eusc-de-east-1": "https://oidc-fips.eusc-de-east-1.api.amazonwebservices.eu/authorize",
		"cn-north-1":     "https://oidc-fips.cn-north-1.api.amazonwebservices.com.cn/authorize",
	}

	for region, expected := range tests {
		ep, err := AuthorizationEndpoint(region)
		require.NoError(t, err, "region %q", region)
		assert.Equal(t, expected, ep, "region %q", region)
	}
}

// TestAuthorizationEndpointFIPSDualStackEmptyRegion verifies that the empty-region
// guard fires before the SDK resolver, so neither "FIPS" nor "dual-stack" appear
// in the error even when both env vars are set.
func TestAuthorizationEndpointFIPSDualStackEmptyRegion(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")

	ep, err := AuthorizationEndpoint("")
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.False(t, strings.Contains(err.Error(), "FIPS"), "empty-region error must not mention FIPS")
	assert.False(t, strings.Contains(err.Error(), "dual-stack"), "empty-region error must not mention dual-stack")
}

// TestAuthorizationEndpointFIPSDualStackResolverError verifies that when the SDK
// resolver fails with both FIPS and dual-stack enabled the error mentions both.
func TestAuthorizationEndpointFIPSDualStackResolverError(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")

	ep, err := authorizationEndpoint("us-east-1", &errResolver{})
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.True(t, strings.Contains(err.Error(), "FIPS"), "combined error should mention FIPS")
	assert.True(t, strings.Contains(err.Error(), "dual-stack"), "combined error should mention dual-stack")
}

// TestAuthorizationEndpointResolverError verifies the plain (non-FIPS,
// non-dual-stack) resolver error path.
func TestAuthorizationEndpointResolverError(t *testing.T) {
	ep, err := authorizationEndpoint("us-east-1", &errResolver{})
	assert.Error(t, err)
	assert.Empty(t, ep)
	assert.False(t, strings.Contains(err.Error(), "FIPS"), "plain error should not mention FIPS")
	assert.False(t, strings.Contains(err.Error(), "dual-stack"), "plain error should not mention dual-stack")
}

// errResolver is a test double that always returns an error from ResolveEndpoint.
type errResolver struct{}

func (r *errResolver) ResolveEndpoint(_ context.Context, _ ssooidc.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return smithyendpoints.Endpoint{}, errors.New("resolver error")
}
