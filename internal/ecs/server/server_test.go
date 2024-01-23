package server

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
	"context"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"golang.org/x/net/nettest"
)

func newRequest(now time.Time) *ecs.ECSClientRequest {
	return &ecs.ECSClientRequest{
		ProfileName: "1234:FooBar",
		Creds: &storage.RoleCredentials{
			RoleName:        "FooBar",
			AccountId:       1234,
			AccessKeyId:     "AccessKeyId",
			SecretAccessKey: "SecretAccessKey",
			SessionToken:    "SessionToken",
			Expiration:      now.UnixMilli(),
		},
	}
}

func TestSlottedCreds(t *testing.T) {
	now := time.Now().Add(95 * time.Second)
	r := newRequest(now)
	es := &EcsServer{
		slottedCreds: map[string]*ecs.ECSClientRequest{},
	}

	// Add creds
	err := es.PutSlottedCreds(r)
	assert.NoError(t, err)

	// get those creds
	resp, err := es.GetSlottedCreds("1234:FooBar")
	assert.NoError(t, err)
	assert.Equal(t, r.ProfileName, resp.ProfileName)

	// can't find missing creds
	_, err = es.GetSlottedCreds("asdfsdf")
	assert.Error(t, err)

	// we can list our crds
	list := es.ListSlottedCreds()
	assert.Equal(t, 1, len(list))
	assert.Equal(t, r.ProfileName, list[0].ProfileName)

	// failure to add expired creds
	now = time.Now().Add(-5 * time.Second)
	err = es.PutSlottedCreds(newRequest(now))
	assert.Error(t, err)

	// didn't actually add the expired creds
	list = es.ListSlottedCreds()
	assert.Equal(t, 1, len(list))
	assert.Equal(t, r.ProfileName, list[0].ProfileName)

	// manually add expired creds which should not be listed
	es.slottedCreds["Expired"] = &ecs.ECSClientRequest{
		ProfileName: "expired",
		Creds: &storage.RoleCredentials{
			Expiration: now.UnixMilli(),
		},
	}
	list = es.ListSlottedCreds()
	assert.Equal(t, 1, len(list))

	// Success delete our creds
	err = es.DeleteSlottedCreds("1234:FooBar")
	assert.NoError(t, err)

	list = es.ListSlottedCreds()
	assert.Empty(t, list)

	// can't delete missing creds
	err = es.DeleteSlottedCreds("1234:FooBar")
	assert.Error(t, err)
}

func TestBaseURL(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	es := &EcsServer{
		listener: l,
	}

	str := es.BaseURL()
	assert.Regexp(t, regexp.MustCompile(`^http://`), str)
}

func TestAuthToken(t *testing.T) {
	es := &EcsServer{
		authToken: "token",
	}

	assert.Equal(t, "token", es.AuthToken())
}

func TestExpiredCredentials(t *testing.T) {
	e := ExpiredCredentials{}
	assert.Equal(t, "Expired Credentials", e.Error())
}

func TestServerWithAuth(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	s, err := NewEcsServer(context.TODO(), "AuthToken", l)
	assert.NoError(t, err)

	go func() {
		err = s.Serve()
	}()

	res, err := http.Get(fmt.Sprintf("http://%s/", l.Addr()))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	l.Close()
}

func TestServerWithoutAuth(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	s, err := NewEcsServer(context.TODO(), "", l)
	assert.NoError(t, err)

	go func() {
		err = s.Serve()
	}()

	res, err := http.Get(fmt.Sprintf("http://%s/", l.Addr()))
	assert.NoError(t, err)
	// nothing was loaded yet, so 404
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	l.Close()
}
