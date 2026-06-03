package main

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAfterApply(t *testing.T) {
	cases := []struct {
		name     string
		apply    func(*RunContext) error
		wantAuth CommandAuth
	}{
		{"CacheCmd", CacheCmd{}.AfterApply, AUTH_REQUIRED},
		{"CompleteCmd", CompleteCmd{}.AfterApply, AUTH_NO_CONFIG},
		{"ConsoleCmd", ConsoleCmd{}.AfterApply, AUTH_REQUIRED},
		{"CredentialsCmd", CredentialsCmd{}.AfterApply, AUTH_REQUIRED},
		{"DefaultCmd", DefaultCmd{}.AfterApply, AUTH_SKIP},
		{"EcsAuthCmd", EcsAuthCmd{}.AfterApply, AUTH_SKIP},
		{"EcsListCmd", EcsListCmd{}.AfterApply, AUTH_SKIP},
		{"EcsLoadCmd", EcsLoadCmd{}.AfterApply, AUTH_REQUIRED},
		{"EcsProfileCmd", EcsProfileCmd{}.AfterApply, AUTH_SKIP},
		{"EcsSSLCmd", EcsSSLCmd{}.AfterApply, AUTH_SKIP},
		{"EcsUnloadCmd", EcsUnloadCmd{}.AfterApply, AUTH_NO_CONFIG},
		{"ExecCmd", ExecCmd{}.AfterApply, AUTH_REQUIRED},
		{"ListCmd", ListCmd{}.AfterApply, AUTH_SKIP},
		{"ListSSORolesCmd", ListSSORolesCmd{}.AfterApply, AUTH_SKIP},
		{"LoginCmd", LoginCmd{}.AfterApply, AUTH_SKIP},
		{"LogoutCmd", LogoutCmd{}.AfterApply, AUTH_SKIP},
		{"ProcessCmd", ProcessCmd{}.AfterApply, AUTH_REQUIRED},
		{"SetupProfilesCmd", SetupProfilesCmd{}.AfterApply, AUTH_REQUIRED},
		{"SetupWizardCmd", SetupWizardCmd{}.AfterApply, AUTH_SKIP},
		{"TagsCmd", TagsCmd{}.AfterApply, AUTH_SKIP},
		{"TimeCmd", TimeCmd{}.AfterApply, AUTH_SKIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rctx := &RunContext{}
			require.NoError(t, tc.apply(rctx))
			assert.Equal(t, tc.wantAuth, rctx.Auth)
		})
	}
}
