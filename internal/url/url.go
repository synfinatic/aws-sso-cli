package url

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
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/skratchdot/open-golang/open"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	// default opener
)

var log logger.CustomLogger

func init() {
	log = logger.GetLogger()
}

// taken from https://github.com/honsiorovskyi/open-url-in-container/blob/1.0.3/launcher.sh
var FIREFOX_PLUGIN_COLORS []string = []string{
	"blue",
	"turquoise",
	"green",
	"yellow",
	"orange",
	"red",
	"pink",
	"purple",
	// "toolbar",  not a valid input, even if it is user selectable
}

var FIREFOX_PLUGIN_ICONS []string = []string{
	"fingerprint",
	"briefcase",
	"dollar",
	"cart",
	"gift",
	"vacation",
	"food",
	"fruit",
	"pet",
	"tree",
	"chill",
	"circle",
	// "fence",  not a valid input, even if it is user selectable
}

const (
	FIREFOX_CONTAINER_FORMAT = "ext+container:name=%s&url=%s&color=%s&icon=%s"
	GRANTED_CONTAINER_FORMAT = "ext+granted-containers:name=%s&url=%s&color=%s&icon=%s"
	DEFAULT_PRE_MSG          = "Please open the following URL in your browser:\n\n"
	DEFAULT_POST_MSG         = "\n\n"
)

// these types & variables make our code easier to unit test
type urlOpenerFunc func(string) error
type urlOpenerWithFunc func(string, string) error
type clipboardWriterFunc func(string) error

var urlOpener urlOpenerFunc = open.Run
var urlOpenerWith urlOpenerWithFunc = open.RunWith
var clipboardWriter clipboardWriterFunc = clipboard.WriteAll

type Action string

const (
	Undef            Action = ""         // undefined
	Clip             Action = "clip"     // copy to clipboard
	Print            Action = "print"    // print message & url to stderr
	PrintUrl         Action = "printurl" // print only the  url to stderr
	Exec             Action = "exec"     // Exec comand
	Open             Action = "open"     // auto-open in default or specified browser
	GrantedContainer Action = "granted-containers"
	OpenUrlContainer Action = "open-url-in-container"
)

func (u Action) IsContainer() bool {
	return u == GrantedContainer || u == OpenUrlContainer
}

// GetConfigProfileAction returns the ConfigProfilesAction for the given Action
func (u Action) GetConfigProfilesAction() ConfigProfilesAction {
	switch u {
	case "print", "printurl", "":
		return ConfigProfilesOpen
	default:
		return ConfigProfilesAction(u)
	}
}

type ConfigProfilesAction string

const (
	ConfigProfilesUndef            ConfigProfilesAction = ""     // undefined
	ConfigProfilesClip             ConfigProfilesAction = "clip" // copy to clipboard
	ConfigProfilesExec             ConfigProfilesAction = "exec" // Exec comand
	ConfigProfilesOpen             ConfigProfilesAction = "open" // auto-open in default or specified browser
	ConfigProfilesGrantedContainer ConfigProfilesAction = "granted-containers"
	ConfigProfilesOpenUrlContainer ConfigProfilesAction = "open-url-in-container"
)

func (u ConfigProfilesAction) IsContainer() bool {
	return u == ConfigProfilesGrantedContainer || u == ConfigProfilesOpenUrlContainer
}

func NewConfigProfilesAction(action string) (ConfigProfilesAction, error) {
	var actionMap = map[string]ConfigProfilesAction{
		"":                      ConfigProfilesUndef,
		"clip":                  ConfigProfilesClip,
		"exec":                  ConfigProfilesExec,
		"open":                  ConfigProfilesOpen,
		"granted-containers":    ConfigProfilesGrantedContainer,
		"open-url-in-container": ConfigProfilesOpenUrlContainer,
	}
	ret, ok := actionMap[action]
	if !ok {
		return ConfigProfilesOpen, fmt.Errorf("invalid ConfigProfilesAction: %s", action)
	}
	return ret, nil
}

func NewAction(action string) (Action, error) {
	var actionMap = map[string]Action{
		"":                      Undef,
		"clip":                  Clip,
		"exec":                  Exec,
		"open":                  Open,
		"print":                 Print,
		"printurl":              PrintUrl,
		"granted-containers":    GrantedContainer,
		"open-url-in-container": OpenUrlContainer,
	}
	ret, ok := actionMap[action]
	if !ok {
		return Open, fmt.Errorf("invalid Action: %s", action)
	}
	return ret, nil
}

type HandleUrl struct {
	Action        Action
	ExecCmd       []string
	Browser       string
	Url           string
	PreMsg        string
	PostMsg       string
	ContainerName string
	Color         string
	Icon          string
}

func NewHandleUrl(action Action, url, browser string, command []string) *HandleUrl {
	if action == Undef {
		action = Open
	}

	if (action == Exec || action.IsContainer()) && len(command) == 0 {
		panic("Unable to call exec or open firefox container with an empty command")
	}

	h := &HandleUrl{
		Action:  action,
		Browser: browser,
		ExecCmd: command,
		Url:     url,
		PreMsg:  DEFAULT_PRE_MSG,
		PostMsg: DEFAULT_POST_MSG,
	}
	return h
}

// ContainerSettings updates our config with the options necessary to open in a container
func (h *HandleUrl) ContainerSettings(name, color, icon string) {
	h.ContainerName = name
	h.Color = color
	h.Icon = icon
}

var printWriter io.Writer = os.Stderr

// Open our url using our config
func (h *HandleUrl) Open() error {
	var err error
	var browser string

	switch h.Action {
	case Clip:
		err = clipboardWriter(h.Url)
		if err == nil {
			log.Info("Please open URL copied to clipboard.\n")
		} else {
			err = fmt.Errorf("unable to copy URL to clipboard: %s", err.Error())
		}

	case Exec:
		err = execWithUrl(h.ExecCmd, h.Url)

	case GrantedContainer:
		url := formatContainerUrl(GRANTED_CONTAINER_FORMAT, h.Url, h.ContainerName, h.Color, h.Icon)
		err = execWithUrl(h.ExecCmd, url)

	case OpenUrlContainer:
		url := formatContainerUrl(FIREFOX_CONTAINER_FORMAT, h.Url, h.ContainerName, h.Color, h.Icon)
		err = execWithUrl(h.ExecCmd, url)

	case Print:
		fmt.Fprintf(printWriter, "%s%s%s", h.PreMsg, h.Url, h.PostMsg)

	case PrintUrl:
		fmt.Fprintf(printWriter, "%s\n", h.Url)

	case Open:
		switch h.Browser {
		case "":
			err = urlOpener(h.Url)
			browser = "default browser"
		default:
			err = urlOpenerWith(h.Url, h.Browser)
		}
		if err != nil {
			err = fmt.Errorf("unable to open URL with %s: %s", browser, err.Error())
		} else {
			log.Info("Opening URL", "browser", browser)
		}

	default:
		err = fmt.Errorf("unsupported Open action: %s", string(h.Action))
	}

	return err
}

// selectElement selects a deterministic pseudo-random option given a string
// as the seed
func selectElement(seed string, options []string) string {
	var v = byte(0)
	var bytes = []byte(seed)

	for i := 0; i < len(seed); i++ {
		v += bytes[i] // overflows
	}
	v %= byte(len(options))
	return options[int(v)]
}

// formatContainerUrl rewrites a targetUrl with the given format and arguments
func formatContainerUrl(format, targetUrl, name, color, icon string) string {
	if !utils.StrListContains(color, FIREFOX_PLUGIN_COLORS) {
		if color != "" {
			log.Warn("Invalid Firefox Container color", "color", color)
		}
		color = selectElement(name, FIREFOX_PLUGIN_COLORS)
	}

	if !utils.StrListContains(icon, FIREFOX_PLUGIN_ICONS) {
		if icon != "" {
			log.Warn("Invalid Firefox Container icon", "icon", icon)
		}
		icon = selectElement(name, FIREFOX_PLUGIN_ICONS)
	}

	return fmt.Sprintf(format, name, url.QueryEscape(targetUrl), color, icon)
}

// execWithUrl runs a command with the given url
func execWithUrl(command []string, url string) error {
	var cmd *exec.Cmd

	program, cmdList, err := commandBuilder(command, url)
	if err != nil {
		return err
	}

	cmdStr := fmt.Sprintf("%s %s", program, strings.Join(cmdList, " "))
	log.Debug("exec command as array", "command", cmdStr)
	cmd = exec.Command(program, cmdList...)

	// add $HOME to our environment
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("HOME=%s", os.Getenv("HOME")))

	//	var stderr bytes.Buffer
	//	cmd.Stderr = &stderr
	err = cmd.Start() // Don't use Run() because sometimes firefox does bad things?
	if err != nil {
		err = fmt.Errorf("unable to exec `%s`: %s", cmdStr, err)
	}
	log.Debug("Opened our URL", "command", command[0])
	return err
}

// used by execWithUrl to build our actual command
func commandBuilder(command []string, url string) (string, []string, error) {
	var program string
	cmdList := []string{}
	replaced := false

	if len(command) < 2 {
		return program, cmdList, fmt.Errorf("invalid UrlExecCommand has fewer than 2 arguments")
	}

	for i, v := range command {
		if i == 0 {
			program = v
			continue
		} else if strings.Contains(v, "%s") {
			replaced = true
			v = fmt.Sprintf(v, url)
		}
		cmdList = append(cmdList, v)
	}

	if !replaced {
		return program, cmdList, fmt.Errorf("invalid UrlExecCommand has no `%%s` for URL")
	}

	// if program is ~/something, expand it
	program = utils.GetHomePath(program)

	return program, cmdList, nil
}

// SSOAuthAction returns the action except in the case where it might use a
// container, in that case it returns a straight Open.  This is so that URLs
// used to do AWS SSO auth use the primary browser session to avoid re-auth
func SSOAuthAction(action Action) Action {
	if action.IsContainer() {
		return Open
	}
	return action
}

const AWS_FEDERATED_URL_FORMAT = "https://%s.signin.%s/federation"

// AWSFederatedUrl generates the region/partition specific URL for the AWS
// Federated endpoint for IAM Identity Center
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func AWSFederatedUrl(ssoRegion string) string {
	if strings.HasPrefix(ssoRegion, "cn-") {
		// china
		return fmt.Sprintf(AWS_FEDERATED_URL_FORMAT, ssoRegion, "amazonaws.cn")
	} else if strings.HasPrefix(ssoRegion, "us-gov-") {
		// US Gov
		return fmt.Sprintf(AWS_FEDERATED_URL_FORMAT, ssoRegion, "amazonaws-us-gov.com")
	}
	// Default
	return fmt.Sprintf(AWS_FEDERATED_URL_FORMAT, ssoRegion, "aws.amazon.com")
}

// AWSConsoleUrl generates the partition specific URL for the AWS Console
func AWSConsoleUrl(ssoRegion, region string) string {
	if strings.HasPrefix(ssoRegion, "cn-") {
		return fmt.Sprintf("https://console.amazonaws.cn/console/home?region=%s", region)
	} else if strings.HasPrefix(ssoRegion, "us-gov-") {
		return fmt.Sprintf("https://console.amazonaws-us-gov.com/console/home?region=%s", region)
	}
	return fmt.Sprintf("https://console.aws.amazon.com/console/home?region=%s", region)
}
