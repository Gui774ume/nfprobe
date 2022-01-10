/*
Copyright © 2022 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package run

import (
	"fmt"
	"strconv"

	"github.com/Gui774ume/nfprobe/pkg/nfprobe"

	"github.com/sirupsen/logrus"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	LogLevel       logrus.Level
	NFProbeOptions nfprobe.Options
}

// LogLevelSanitizer is a log level sanitizer that ensures that the provided log level exists
type LogLevelSanitizer struct {
	logLevel *logrus.Level
}

// NewLogLevelSanitizer creates a new instance of LogLevelSanitizer. The sanitized level will be written in the provided
// logrus level
func NewLogLevelSanitizer(sanitizedLevel *logrus.Level) *LogLevelSanitizer {
	*sanitizedLevel = logrus.DebugLevel
	return &LogLevelSanitizer{
		logLevel: sanitizedLevel,
	}
}

func (lls *LogLevelSanitizer) String() string {
	return fmt.Sprintf("%v", *lls.logLevel)
}

func (lls *LogLevelSanitizer) Set(val string) error {
	sanitized, err := logrus.ParseLevel(val)
	if err != nil {
		return err
	}
	*lls.logLevel = sanitized
	return nil
}

func (lls *LogLevelSanitizer) Type() string {
	return "string"
}

// NFProbeOptionsSanitizer is used to sanitize the values passed to NFProbe
type NFProbeOptionsSanitizer struct {
	options *nfprobe.Options
	field   string
}

// NewNFProbeOptionsSanitizer creates a new instance of NewNFProbeOptionsSanitizer
func NewNFProbeOptionsSanitizer(options *nfprobe.Options, field string) *NFProbeOptionsSanitizer {
	return &NFProbeOptionsSanitizer{
		options: options,
		field:   field,
	}
}

func (nos *NFProbeOptionsSanitizer) String() string {
	switch nos.field {
	case "hook":
		return fmt.Sprintf("%v", nos.options.Hook)
	case "proto":
		return fmt.Sprintf("%v", nos.options.NFProto)
	case "verdict":
		return fmt.Sprintf("%v", nos.options.Verdict)
	case "packet-type":
		return fmt.Sprintf("%v", nos.options.PacketType)
	case "netns":
		return fmt.Sprintf("%v", nos.options.NetworkNamespaceID)
	case "in-ifindex":
		return fmt.Sprintf("%v", nos.options.InDeviceIfindex)
	case "out-ifindex":
		return fmt.Sprintf("%v", nos.options.OutDeviceIfindex)
	default:
		return ""
	}
}

func (nos *NFProbeOptionsSanitizer) Set(val string) error {
	switch nos.field {
	case "hook":
		h := nfprobe.NewNFHook(val)
		if h != nil {
			nos.options.Hook = append(nos.options.Hook, *h)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid NFHook", val)
		}
	case "proto":
		p := nfprobe.NewNFProto(val)
		if p != nil {
			nos.options.NFProto = append(nos.options.NFProto, *p)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid NFProto", val)
		}
	case "packet-type":
		t := nfprobe.NewPacketType(val)
		if t != nil {
			nos.options.PacketType = append(nos.options.PacketType, *t)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid PacketType", val)
		}
	case "verdict":
		v := nfprobe.NewVerdict(val)
		if v != nil {
			nos.options.Verdict = append(nos.options.Verdict, *v)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid Verdict", val)
		}
	case "netns":
		ns, err := strconv.Atoi(val)
		if err == nil {
			nos.options.NetworkNamespaceID = append(nos.options.NetworkNamespaceID, ns)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid NetworkNamespaceID: %v", val, err)
		}
	case "in-ifindex":
		i, err := strconv.Atoi(val)
		if err == nil {
			nos.options.InDeviceIfindex = append(nos.options.InDeviceIfindex, i)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid input device ifindex: %v", val, err)
		}
	case "out-ifindex":
		i, err := strconv.Atoi(val)
		if err == nil {
			nos.options.OutDeviceIfindex = append(nos.options.OutDeviceIfindex, i)
			return nil
		} else {
			return fmt.Errorf("%s is not a valid output device ifindex: %v", val, err)
		}
	default:
		return nil
	}
}

func (nos *NFProbeOptionsSanitizer) Type() string {
	return "array"
}
