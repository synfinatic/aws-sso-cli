package time

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ParseTimeString converts a standard RFC3339 time string to Unix Epoch
func ParseTimeString(t string) (int64, error) {
	i, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return 0, fmt.Errorf("unable to parse %s: %s", t, err.Error())
	}
	return i.Unix(), nil
}

// Returns the MMm or HHhMMm or 'Expired' if no time remains
func TimeRemain(expires int64, space bool) (string, error) {
	d := time.Until(time.Unix(expires, 0))
	if d <= 0 {
		return "Expired", nil
	}

	s := strings.Replace(d.Truncate(time.Minute).String(), "0s", "", 1)
	if strings.Compare(s, "") == 0 {
		s = "< 1m"
	}

	if space {
		// space between min & hour and minutes.  Add min mark if it is missing
		re := regexp.MustCompile(`\A(\d+)h(\d+)m?\z`)
		s = re.ReplaceAllString(s, "${1}h ${2}m")

		// two spaces for single digit min
		padMin := regexp.MustCompile(`\A(\d+h) (\dm)\z`)
		s = padMin.ReplaceAllString(s, "$1  $2")

		// padd out to 7 chars
		s = fmt.Sprintf("%7s", s)
	}

	// Just return the number of MMm or HHhMMm
	return s, nil
}
