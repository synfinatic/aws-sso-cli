package fileutils

import (
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/flexlog"
)

var log flexlog.FlexLogger

func init() {
	log = logger.GetLogger()
}
