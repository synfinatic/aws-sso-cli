package time

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseTimeString(t *testing.T) {
	t.Parallel()

	x, e := ParseTimeString("1970-01-01T00:00:00Z")
	assert.NoError(t, e)
	assert.Equal(t, int64(0), x)

	_, e = ParseTimeString("00:00:00 +0000 GMT")
	assert.Error(t, e)
}

func TestTimeRemain(t *testing.T) {
	t.Parallel()

	x, e := TimeRemain(0, false)
	assert.NoError(t, e)
	assert.Equal(t, "Expired", x)

	d, _ := time.ParseDuration("5m1s")
	future := time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, "     5m", x)

	x, e = TimeRemain(future.Unix(), false)
	assert.NoError(t, e)
	assert.Equal(t, "5m", x)

	d, _ = time.ParseDuration("5h5m1s")
	future = time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, " 5h  5m", x)

	x, e = TimeRemain(future.Unix(), false)
	assert.NoError(t, e)
	assert.Equal(t, "5h5m", x)

	// truncate down to < 1min
	d, _ = time.ParseDuration("55s")
	future = time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, "   < 1m", x)

	d, _ = time.ParseDuration("25s")
	future = time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, "   < 1m", x)
}
