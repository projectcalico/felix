// Copyright (c) 2016 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const (
	MinIptablesMarkBits = 2
)

type metadata struct {
	Name              string
	Default           interface{}
	ZeroValue         interface{}
	NonZero           bool
	DieOnParseFailure bool
	Local             bool
}

func (m *metadata) getMetadata() *metadata {
	return m
}

func (m *metadata) parseFailed(raw, msg string) error {
	return errors.New(
		fmt.Sprintf("Failed to parse config parameter %v; value %#v: %v",
			m.Name, raw, msg))
}

func (m *metadata) setDefault(config *Config) {
	log.Debugf("Defaulting: %v to %v", m.Name, m.Default)
	field := reflect.ValueOf(config).Elem().FieldByName(m.Name)
	value := reflect.ValueOf(m.Default)
	field.Set(value)
}

type boolParam struct {
	metadata
}

func (p *boolParam) Parse(raw string) (interface{}, error) {
	switch strings.ToLower(raw) {
	case "true", "1", "yes", "y", "t":
		return true, nil
	case "false", "0", "no", "n", "f":
		return false, nil
	}
	return nil, p.parseFailed(raw, "invalid boolean")
}

type intParam struct {
	metadata
	Min int
	Max int
}

func (p *intParam) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseInt(raw, 0, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid int")
		return nil, err
	}
	result := int(value)
	if result < p.Min {
		err = p.parseFailed(raw,
			fmt.Sprintf("value must be at least %v", p.Min))
	} else if result > p.Max {
		err = p.parseFailed(raw,
			fmt.Sprintf("value must be at most %v", p.Max))
	}
	return result, err
}

type int32Param struct {
	metadata
}

func (p *int32Param) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseInt(raw, 0, 32)
	if err != nil {
		err = p.parseFailed(raw, "invalid 32-bit int")
		return nil, err
	}
	result := int32(value)
	return result, err
}

type floatParam struct {
	metadata
}

func (p *floatParam) Parse(raw string) (result interface{}, err error) {
	result, err = strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	return
}

type regexpParam struct {
	metadata
	Regexp *regexp.Regexp
	Msg    string
}

func (p *regexpParam) Parse(raw string) (result interface{}, err error) {
	if !p.Regexp.MatchString(raw) {
		err = p.parseFailed(raw, p.Msg)
	} else {
		result = raw
	}
	return
}

type fileParam struct {
	metadata
	MustExist bool
}

func (p *fileParam) Parse(raw string) (result interface{}, err error) {
	if p.MustExist && raw != "" {
		_, err = os.Stat(raw)
		if err != nil {
			log.Errorf("Failed to access %v: %v", raw, err)
			err = p.parseFailed(raw, "failed to access file")
			return
		}
	}
	result = raw
	return
}

type ipv4Param struct {
	metadata
}

func (p *ipv4Param) Parse(raw string) (result interface{}, err error) {
	result = net.ParseIP(raw)
	if result == nil {
		err = p.parseFailed(raw, "invalid IP")
	}
	return
}

type portListParam struct {
	metadata
}

func (p *portListParam) Parse(raw string) (interface{}, error) {
	result := []int{}
	for _, portStr := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			err = p.parseFailed(raw, "ports should be integers")
			return nil, err
		}
		if port < 0 || port > 65535 {
			err = p.parseFailed(raw, "ports must be in range 0-65535")
			return nil, err
		}
		result = append(result, int(port))
	}
	return result, nil
}

type endpointListParam struct {
	metadata
}

func (p *endpointListParam) Parse(raw string) (result interface{}, err error) {
	value := strings.Split(raw, ",")
	scheme := ""
	for _, endpoint := range value {
		endpoint = strings.Trim(endpoint, " ")
		var url *url.URL
		url, err = url.Parse(endpoint)
		if err != nil {
			err = p.parseFailed(raw,
				fmt.Sprintf("%v is not a valid URL", endpoint))
			return
		}
		if scheme != "" && url.Scheme != scheme {
			err = p.parseFailed(raw,
				"all endpoints must have the same scheme")
			return
		}
		if url.Opaque != "" || url.User != nil || url.Path != "" ||
			url.RawPath != "" || url.RawQuery != "" ||
			url.Fragment != "" {
			err = p.parseFailed(raw,
				"endpoint contained unsupported URL part; "+
					"expected http(s)://hostname:port only.")
			return
		}
		value = append(value, endpoint)
	}
	result = value
	return
}

type markBitmaskParam struct {
	metadata
}

func (p *markBitmaskParam) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		log.Warningf("Failed to parse %#v as an int: %v", raw, err)
		err = p.parseFailed(raw, "invalid mark: should be 32-bit int")
		return nil, err
	}
	result := uint32(value)
	bitCount := uint32(0)
	for i := uint(0); i < 32; i++ {
		bit := (result >> i) & 1
		bitCount += bit
	}
	if bitCount < MinIptablesMarkBits {
		err = p.parseFailed(raw,
			fmt.Sprintf("invalid mark: needs to have %v bits set",
				MinIptablesMarkBits))
	}
	return result, err
}

type oneofListParam struct {
	metadata
	lowerCaseOptionsToCanonical map[string]string
}

func (p *oneofListParam) Parse(raw string) (result interface{}, err error) {
	result, ok := p.lowerCaseOptionsToCanonical[strings.ToLower(raw)]
	if !ok {
		err = p.parseFailed(raw, "unknown option")
	}
	return
}
