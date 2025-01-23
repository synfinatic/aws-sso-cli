package utils

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
)

func TestBellSkipper(t *testing.T) {
	b := BellSkipper{}

	bytes := []byte("this is my bellskipper buffer\n")
	i, err := b.Write(bytes)
	assert.NoError(t, err)
	assert.Equal(t, len(bytes), i)
	assert.NoError(t, b.Close())

	bytes = []byte{7}
	i, err = b.Write(bytes)
	assert.NoError(t, err)
	assert.Equal(t, 0, i)
}
