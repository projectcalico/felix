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
	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend/etcd"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	IfaceNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)
	AuthorityRegexp = regexp.MustCompile(`^[^:/]+:\d+$`)
	HostnameRegexp  = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
)

const (
	maxUint = ^uint(0)
	maxInt  = int(maxUint >> 1)
	minInt  = -maxInt - 1
)

// Source of a config value.  Values from higher-numbered sources override
// those from lower-numbered sources.  Note: some parameters (such as those
// needed to connect to the datastore) can only be set from a local source.
type Source uint8

const (
	Default = iota
	DatastoreGlobal
	DatastorePerHost
	ConfigFile
	EnvironmentVariable
)

func (source Source) String() string {
	switch source {
	case Default:
		return "<default>"
	case DatastoreGlobal:
		return "datastore (global)"
	case DatastorePerHost:
		return "datastore (per-host)"
	case ConfigFile:
		return "config file"
	case EnvironmentVariable:
		return "environment variable"
	}
	return fmt.Sprintf("<unknown(%v)>", uint8(source))
}

func (source Source) Local() bool {
	switch source {
	case Default, ConfigFile, EnvironmentVariable:
		return true
	default:
		return false
	}
}

// Config contains the best, parsed config values loaded from the various sources.
// We use tags to control the parsing and validation.
type Config struct {
	// Configuration parameters.

	FelixHostname string `config:"hostname;;local,non-zero"`

	EtcdAddr      string   `config:"authority;127.0.0.1:2379;local"`
	EtcdScheme    string   `config:"oneof(http,https);http;local"`
	EtcdKeyFile   string   `config:"file(must-exist);;local"`
	EtcdCertFile  string   `config:"file(must-exist);;local"`
	EtcdCaFile    string   `config:"file(must-exist);;local"`
	EtcdEndpoints []string `config:"endpoint-list;;local"`

	StartupCleanupDelay       int `config:"int;30"`
	PeriodicResyncInterval    int `config:"int;3600"`
	HostInterfacePollInterval int `config:"int;10"`

	IptablesRefreshInterval int `config:"int;60"`

	MetadataAddr string `config:"hostname;127.0.0.1;die-on-fail"`
	MetadataPort int    `config:"int(0,65535);8775;die-on-fail"`

	InterfacePrefix string `config:"iface-name;cali;non-zero,die-on-fail"`

	DefaultEndpointToHostAction string `config:"oneof(DROP,RETURN,ACCEPT);DROP;non-zero,die-on-fail"`
	DropActionOverride          string `config:"oneof(DROP,ACCEPT,LOG-and-DROP,LOG-and-ACCEPT);DROP;non-zero,die-on-fail"`

	LogFilePath           string `config:"file;/var/log/calico/felix.log;die-on-fail"`
	EtcdDriverLogFilePath string `config:"file;/var/log/calico/felix-etcd.log"`

	LogSeverityFile   string `config:"oneof(DEBUG,INFO,WARNING,ERROR,CRITICAL);INFO"`
	LogSeveritySys    string `config:"oneof(DEBUG,INFO,WARNING,ERROR,CRITICAL);INFO"`
	LogSeverityScreen string `config:"oneof(DEBUG,INFO,WARNING,ERROR,CRITICAL);INFO"`

	IpInIpEnabled    bool   `config:"bool;false"`
	IpInIpMtu        int    `config:"int;1440;non-zero"`
	IpInIpTunnelAddr net.IP `config:"ipv4;"`

	ReportingIntervalSecs int `config:"int;30"`
	ReportingTTLSecs      int `config:"int;90"`

	EndpointReportingEnabled   bool    `config:"bool;false"`
	EndpointReportingDelaySecs float64 `config:"float;1.0"`

	MaxIpsetSize int `config:"int;1048576;non-zero"`

	IptablesMarkMask uint32 `config:"mark-bitmask;0xff000000;non-zero,die-on-fail"`

	PrometheusMetricsEnabled        bool `config:"bool;false"`
	PrometheusMetricsPort           int  `config:"int(0,65535);9091"`
	EtcdDriverPrometheusMetricsPort int  `config:"int(0,65535);9092"`

	FailsafeInboundHostPorts  []int `config:"port-list;22;die-on-fail"`
	FailsafeOutboundHostPorts []int `config:"port-list;2379,2380,4001,7001;die-on-fail"`

	// State tracking.

	// nameToSource tracks where we loaded each config param from.
	nameToSource map[string]Source
	RawValues    map[string]string
	Err          error
}

// Load parses and merges the rawData from one particular source into this config object.
// If there is a config value already loaded from a higher-priority source, then
// the new value will be ignored (after validation).
func (config *Config) UpdateFrom(rawData map[string]string, source Source) (changed bool, err error) {
	glog.V(2).Infof("Merging in config from %v: %v", source, rawData)
	for rawName, rawValue := range rawData {
		currentSource := config.nameToSource[rawName]
		param, ok := knownParams[strings.ToLower(rawName)]
		if !ok {
			if source >= currentSource {
				// Stash the raw value in case it's useful for
				// a plugin.  Since we don't know the canonical
				// name, use the raw name.
				config.RawValues[rawName] = rawValue
				config.nameToSource[rawName] = source
			}
			glog.Warningf("Ignoring unknown configuration parameter: %v", rawName)
			continue
		}
		metadata := param.getMetadata()
		name := metadata.Name
		if metadata.Local && !source.Local() {
			glog.Warningf("Ignoring local-only configuration for %v from %v",
				name, source)
			continue
		}

		glog.V(2).Infof("Parsing value for %v: %v (from %v)",
			name, rawValue, source)
		var value interface{}
		if strings.ToLower(rawValue) == "none" {
			if metadata.NonZero {
				err = errors.New("Non-zero field cannot be set to none")
				glog.Errorf(
					"Failed to parse value for %v: %v from source %v. %v",
					name, rawValue, source, err)
				config.Err = err
				return
			}
			glog.V(2).Infof("Value set to 'none', replacing with zero-value: %#v.",
				value)
			value = metadata.ZeroValue
		} else {
			value, err = param.Parse(rawValue)
			if err != nil {
				glog.Errorf("%v (source %v)", err, source)
				if metadata.DieOnParseFailure {
					glog.Errorf("Cannot continue with invalid value for %v.", name)
					config.Err = err
					return
				} else {
					glog.Errorf("Replacing invalid value with default value for %v: %v",
						name, metadata.Default)
					value = metadata.Default
					err = nil
				}
			}
		}

		field := reflect.ValueOf(config).Elem().FieldByName(name)
		currentValue := field.Interface()
		if currentValue == value {
			glog.V(3).Infof("Value of %v hasn't changed, skipping.", name)
			continue
		}

		glog.V(2).Infof("Parsed value for %v: %v (from %v)",
			name, value, source)
		if source < currentSource {
			glog.V(2).Infof("Skipping config value for %v from %v; "+
				"already have a value from %v", source, currentSource)
			continue
		}
		glog.V(2).Infof(
			"Now using %v value from %v (preferred to "+
				"previous value from %v)",
			name, source, currentSource)
		field.Set(reflect.ValueOf(value))
		if config.RawValues[name] != rawValue {
			glog.V(1).Infof("Configuration value %v changed from %v to %v",
				name, config.RawValues[name], rawValue)
			changed = true
		}
		config.RawValues[name] = rawValue
		config.nameToSource[name] = source
	}
	return
}

func (config *Config) EndpointReportingDelay() time.Duration {
	return time.Duration(config.EndpointReportingDelaySecs*1000000) * time.Microsecond
}

func (config *Config) DatastoreConfig() api.ClientConfig {
	var etcdEndpoints string
	if len(config.EtcdEndpoints) == 0 {
		etcdEndpoints = config.EtcdScheme + "://" + config.EtcdAddr
	} else {
		etcdEndpoints = strings.Join(config.EtcdEndpoints, ",")
	}
	etcdCfg := &etcd.EtcdConfig{
		EtcdEndpoints:  etcdEndpoints,
		EtcdKeyFile:    config.EtcdKeyFile,
		EtcdCertFile:   config.EtcdCertFile,
		EtcdCACertFile: config.EtcdCaFile,
	}
	return api.ClientConfig{
		BackendType:   api.EtcdV2,
		BackendConfig: etcdCfg,
	}
}

// Validate() performs cross-field validation.
func (config *Config) Validate() (err error) {
	if config.FelixHostname == "" {
		err = errors.New("Failed to determine hostname")
	}

	if len(config.EtcdEndpoints) == 0 {
		if config.EtcdScheme == "" {
			err = errors.New("EtcdEndpoints and EtcdScheme both missing")
		}
		if config.EtcdAddr == "" {
			err = errors.New("EtcdEndpoints and EtcdAddr both missing")
		}
	}

	if err != nil {
		config.Err = err
	}
	return
}

var knownParams map[string]param

func loadParams() {
	knownParams = make(map[string]param)
	config := Config{}
	kind := reflect.TypeOf(config)
	metaRegexp := regexp.MustCompile(`^([^;(]+)(?:\(([^)]*)\))?;` +
		`([^;]*)(?:;` +
		`([^;]*))?$`)
	for ii := 0; ii < kind.NumField(); ii++ {
		field := kind.Field(ii)
		tag := field.Tag.Get("config")
		if tag == "" {
			continue
		}
		captures := metaRegexp.FindStringSubmatch(tag)
		if len(captures) == 0 {
			glog.Fatalf("Failed to parse metadata for config param %v", field.Name)
		}
		glog.V(3).Infof("%v: metadata captures: %#v", field.Name, captures)
		kind := captures[1]       // Type: "int|oneof|bool|port-list|..."
		kindParams := captures[2] // Parameters for the type: e.g. for oneof "http,https"
		defaultStr := captures[3] // Default value e.g "1.0"
		flags := captures[4]
		var param param
		var err error
		switch kind {
		case "bool":
			param = &boolParam{}
		case "int":
			min := minInt
			max := maxInt
			if kindParams != "" {
				minAndMax := strings.Split(kindParams, ",")
				min, err = strconv.Atoi(minAndMax[0])
				if err != nil {
					glog.Fatalf("Failed to parse min value for %v", field.Name)
				}
				max, err = strconv.Atoi(minAndMax[1])
				if err != nil {
					glog.Fatalf("Failed to parse max value for %v", field.Name)
				}
			}
			param = &intParam{Min: min, Max: max}
		case "int32":
			param = &int32Param{}
		case "mark-bitmask":
			param = &markBitmaskParam{}
		case "float":
			param = &floatParam{}
		case "iface-name":
			param = &regexpParam{Regexp: IfaceNameRegexp,
				Msg: "invalid Linux interface name"}
		case "file":
			if kindParams != "" && kindParams != "must-exist" {
				glog.Fatalf("Bad type params for 'file': %#v",
					kindParams)
			}
			param = &fileParam{MustExist: kindParams == "must-exist"}
		case "authority":
			param = &regexpParam{Regexp: AuthorityRegexp,
				Msg: "invalid URL authority"}
		case "ipv4":
			param = &ipv4Param{}
		case "endpoint-list":
			param = &endpointListParam{}
		case "port-list":
			param = &portListParam{}
		case "hostname":
			param = &regexpParam{Regexp: HostnameRegexp,
				Msg: "invalid hostname"}
		case "oneof":
			options := strings.Split(kindParams, ",")
			lowerCaseToCanon := make(map[string]string)
			for _, option := range options {
				lowerCaseToCanon[strings.ToLower(option)] = option
			}
			param = &oneofListParam{
				lowerCaseOptionsToCanonical: lowerCaseToCanon}
		default:
			glog.Fatalf("Unknown type of parameter: %v", kind)
		}

		metadata := param.getMetadata()
		metadata.Name = field.Name
		metadata.ZeroValue = reflect.ValueOf(config).FieldByName(field.Name).Interface()
		if strings.Index(flags, "non-zero") > -1 {
			metadata.NonZero = true
		}
		if strings.Index(flags, "die-on-fail") > -1 {
			metadata.DieOnParseFailure = true
		}
		if strings.Index(flags, "local") > -1 {
			metadata.Local = true
		}

		if defaultStr != "" {
			// Parse the default value and save it in the metadata. Doing
			// that here ensures that we syntax-check the defaults now.
			defaultVal, err := param.Parse(defaultStr)
			if err != nil {
				glog.Fatalf("Invalid default value: %v", err)
			}
			metadata.Default = defaultVal
		} else {
			metadata.Default = metadata.ZeroValue
		}
		knownParams[strings.ToLower(field.Name)] = param
	}
}

func New() *Config {
	if knownParams == nil {
		loadParams()
	}
	p := &Config{
		RawValues:    make(map[string]string),
		nameToSource: make(map[string]Source),
	}
	for _, param := range knownParams {
		param.setDefault(p)
	}
	hostname, err := os.Hostname()
	if err != nil {
		glog.Warningf("Failed to get hostname from kernel, "+
			"trying HOSTNAME variable: %v", err)
		hostname = os.Getenv("HOSTNAME")
	}
	p.FelixHostname = hostname
	return p
}

type param interface {
	getMetadata() *metadata
	Parse(raw string) (result interface{}, err error)
	setDefault(*Config)
}
