package awsparse

import (
	"fmt"
	"strconv"
	"strings"
)

const MAX_AWS_ACCOUNTID = 999999999999

// ParseRoleARN parses an ARN representing a role in long or short format
func ParseRoleARN(arn string) (int64, string, error) {
	s := strings.Split(arn, ":")
	var accountid, role string
	switch len(s) {
	case 2:
		// short account:Role format
		accountid = s[0]
		role = s[1]
	case 6:
		// long format for arn:aws:iam::XXXXXXXXXX:role/YYYYYYYY
		accountid = s[4]
		s = strings.Split(s[5], "/")
		if len(s) != 2 {
			return 0, "", fmt.Errorf("unable to parse ARN: %s", arn)
		}
		role = s[1]
	default:
		return 0, "", fmt.Errorf("unable to parse ARN: %s", arn)
	}

	aId, err := strconv.ParseInt(accountid, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("unable to parse ARN: %s", arn)
	}
	if aId < 0 {
		return 0, "", fmt.Errorf("invalid AccountID: %d", aId)
	}
	return aId, role, nil
}

// ParseUserARN parses an ARN representing a user in long or short format
func ParseUserARN(arn string) (int64, string, error) {
	return ParseRoleARN(arn)
}

// MakeRoleARN create an IAM Role ARN using an int64 for the account
func MakeRoleARN(account int64, name string) string {
	a, err := AccountIdToString(account)
	if err != nil {
		panic(fmt.Sprintf("unable to MakeRoleARN: %s", err.Error()))
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", a, name)
}

// MakeUserARN create an IAM User ARN using an int64 for the account
func MakeUserARN(account int64, name string) string {
	a, err := AccountIdToString(account)
	if err != nil {
		panic(fmt.Sprintf("unable to MakeUserARN: %s", err.Error()))
	}
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", a, name)
}

// MakeRoleARNs creates an IAM Role ARN using a string for the account and role
func MakeRoleARNs(account, name string) string {
	x, err := AccountIdToInt64(account)
	if err != nil {
		panic(fmt.Sprintf("unable to MakeRoleARNs: %s", err.Error()))
	}

	a, _ := AccountIdToString(x)
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", a, name)
}

// AccountIdToString returns a string version of AWS AccountID with leading zeroes
func AccountIdToString(a int64) (string, error) {
	if a < 0 || a > MAX_AWS_ACCOUNTID {
		return "", fmt.Errorf("invalid AWS AccountId: %d", a)
	}
	return fmt.Sprintf("%012d", a), nil
}

// AccountIdToInt64 returns an int64 version of AWS AccountID in base10
func AccountIdToInt64(a string) (int64, error) {
	var x int64
	var err error

	if strings.Contains(a, "e+") {
		// AWS AccountID is in scientific notation
		f, err := strconv.ParseFloat(a, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid AWS AccountId: %s", a)
		}
		x = int64(f)
	} else {
		x, err = strconv.ParseInt(a, 10, 64)
		if err != nil {
			return 0, err
		}
	}
	if x < 0 || x > MAX_AWS_ACCOUNTID {
		return 0, fmt.Errorf("invalid AWS AccountId: %s", a)
	}
	return x, nil
}
