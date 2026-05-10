package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAuthWorkflow(t *testing.T) {
	assert.NoError(t, ValidateAuthWorkflow(AuthWorkflow("")))
	assert.NoError(t, ValidateAuthWorkflow(AuthWorkflowDeviceCode))
	assert.NoError(t, ValidateAuthWorkflow(AuthWorkflowPKCE))

	err := ValidateAuthWorkflow(AuthWorkflow("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AuthWorkflow")
}

func TestAuthWorkflowValid(t *testing.T) {
	assert.True(t, AuthWorkflowDeviceCode.Valid())
	assert.True(t, AuthWorkflowPKCE.Valid())
	assert.False(t, AuthWorkflow("").Valid())
	assert.False(t, AuthWorkflow("unknown").Valid())
}

func TestAuthWorkflowOrDefault(t *testing.T) {
	assert.Equal(t, AuthWorkflowPKCE, AuthWorkflow("").OrDefault())
	assert.Equal(t, AuthWorkflowPKCE, AuthWorkflowPKCE.OrDefault())
	assert.Equal(t, AuthWorkflowDeviceCode, AuthWorkflowDeviceCode.OrDefault())
}
