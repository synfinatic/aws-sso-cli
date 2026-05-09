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
