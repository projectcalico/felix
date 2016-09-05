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

package main

import (
	"encoding/binary"
	"flag"
	"github.com/docopt/docopt-go"
	pb "github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/projectcalico/calico/go/datastructures/ip"
	"github.com/projectcalico/calico/go/felix/calc"
	"github.com/projectcalico/calico/go/felix/config"
	_ "github.com/projectcalico/calico/go/felix/config"
	"github.com/projectcalico/calico/go/felix/proto"
	"github.com/projectcalico/calico/go/felix/status"
	"github.com/tigera/libcalico-go/lib/backend"
	bapi "github.com/tigera/libcalico-go/lib/backend/api"
	"github.com/tigera/libcalico-go/lib/backend/model"
	"io"
	"os"
	"os/exec"
	"time"
)

const usage = `Felix, the Calico per-host daemon.

Usage:
  calico-felix [-c <config>]

Options:
  -c --config-file=<config>  Config file to load [default: /etc/calico/felix.cfg].
`

func main() {
	// Parse command-line args.
	arguments, err := docopt.Parse(usage, nil, true, "calico-felix 1.5", false)
	if err != nil {
		println(usage)
		glog.Fatalf("Failed to parse usage, exiting: %v", err)
	}

	// Intitialise logging early so we can trace out config parsing.
	flag.CommandLine.Parse(nil)
	if os.Getenv("GLOG") != "" {
		flag.Lookup("logtostderr").Value.Set("true")
		flag.Lookup("v").Value.Set(os.Getenv("GLOG"))
	}
	glog.V(1).Infof("Command line arguments: %v", arguments)

	// Load the configuration from all the different sources and merge.
	// Keep retrying on failure.
	glog.V(1).Infof("Loading configuration...")
	var datastore bapi.Client
	var configParams *config.Config
configRetry:
	for {
		// Load locally-defined config, including the datastore connection
		// parameters. First the environment variables.
		configParams = config.New()
		envConfig := config.LoadConfigFromEnvironment(os.Environ())
		// Then, the config file.
		configFile := arguments["--config-file"].(string)
		fileConfig, err := config.LoadConfigFile(configFile)
		if err != nil {
			glog.Errorf("Failed to load configuration file, %s: %s",
				configFile, err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		// Parse and merge the local config.
		configParams.UpdateFrom(envConfig, config.EnvironmentVariable)
		configParams.UpdateFrom(fileConfig, config.ConfigFile)
		if configParams.Err != nil {
			glog.Errorf("Failed to parse configuration: %s", configParams.Err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		// We should now have enough config to connect to the datastore
		// so we can load the remainder of the config.
		datastoreConfig := configParams.DatastoreConfig()
		datastore, err = backend.NewClient(datastoreConfig)
		if err != nil {
			glog.Errorf("Failed to connect to datastore: %v", err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		globalConfig, hostConfig := loadConfigFromDatastore(datastore,
			configParams.FelixHostname)
		configParams.UpdateFrom(globalConfig, config.DatastoreGlobal)
		configParams.UpdateFrom(hostConfig, config.DatastorePerHost)
		configParams.Validate()
		if configParams.Err != nil {
			glog.Fatalf("Failed to parse/validate configuration from datastore: %s",
				configParams.Err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		break
	}

	// If we get here, we've loaded the configuration and we're ready to
	// start the dataplane driver.
	glog.V(1).Infof("Successfully loaded configuration: %+v", configParams)

	// Create a pair of pipes, one for sending messages to the dataplane
	// driver, the other for receiving.
	toDriverR, toDriverW, err := os.Pipe()
	if err != nil {
		glog.Fatalf("Failed to open pipe for dataplane driver: %v", err)
	}
	fromDriverR, fromDriverW, err := os.Pipe()
	if err != nil {
		glog.Fatalf("Failed to open pipe for dataplane driver: %v", err)
	}

	cmd := exec.Command("calico-iptables-plugin")
	driverOut, err := cmd.StdoutPipe()
	if err != nil {
		glog.Fatal("Failed to create pipe for dataplane driver")
	}
	driverErr, err := cmd.StderrPipe()
	if err != nil {
		glog.Fatal("Failed to create pipe for dataplane driver")
	}
	go io.Copy(os.Stdout, driverOut)
	go io.Copy(os.Stderr, driverErr)
	cmd.ExtraFiles = []*os.File{toDriverR, fromDriverW}
	if err := cmd.Start(); err != nil {
		glog.Fatalf("Failed to start dataplane driver: %v", err)
	}
	go func() {
		err := cmd.Wait()
		glog.Fatalf("Dataplane driver died, must restart: %v", err)
	}()

	// Now the sub-process is running, close our copy of the file handles
	// for the child's end of the pipes.
	if err := toDriverR.Close(); err != nil {
		glog.Fatalf("Failed to close parent's copy of pipe")
	}
	if err := fromDriverW.Close(); err != nil {
		glog.Fatalf("Failed to close parent's copy of pipe")
	}

	glog.Info("Starting the dataplane driver")
	felixConn := NewDataplaneConn(configParams, datastore, toDriverW, fromDriverR)
	felixConn.Start()
	felixConn.Join()
}

func loadConfigFromDatastore(datastore bapi.Client, hostname string) (globalConfig, hostConfig map[string]string) {
	for {
		glog.V(1).Info("Loading global config from datastore")
		kvs, err := datastore.List(model.GlobalConfigListOptions{})
		if err != nil {
			glog.Errorf("Failed to load config from datastore: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		globalConfig = make(map[string]string)
		for _, kv := range kvs {
			key := kv.Key.(model.GlobalConfigKey)
			value := kv.Value.(string)
			globalConfig[key.Name] = value
		}

		glog.V(1).Infof("Loading per-host config from datastore; hostname=%v", hostname)
		kvs, err = datastore.List(
			model.HostConfigListOptions{Hostname: hostname})
		if err != nil {
			glog.Errorf("Failed to load config from datastore: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		hostConfig = make(map[string]string)
		for _, kv := range kvs {
			key := kv.Key.(model.HostConfigKey)
			value := kv.Value.(string)
			hostConfig[key.Name] = value
		}
		glog.V(1).Info("Loaded config from datastore")
		break
	}
	return globalConfig, hostConfig
}

type ipUpdate struct {
	ipset string
	ip    ip.Addr
}

type DataplaneConn struct {
	config          *config.Config
	toFelix         chan interface{}
	endpointUpdates chan interface{}
	inSync          chan bool
	failed          chan bool
	felixReader     io.Reader
	felixWriter     io.Writer
	datastore       bapi.Client
	statusReporter  *status.EndpointStatusReporter

	datastoreInSync bool

	firstStatusReportSent bool
	nextSeqNumber         uint64
}

type Startable interface {
	Start()
}

func NewDataplaneConn(configParams *config.Config,
	datastore bapi.Client,
	toDriver io.Writer,
	fromDriver io.Reader) *DataplaneConn {
	felixConn := &DataplaneConn{
		config:          configParams,
		datastore:       datastore,
		toFelix:         make(chan interface{}),
		endpointUpdates: make(chan interface{}),
		inSync:          make(chan bool, 1),
		failed:          make(chan bool),
		felixReader:     fromDriver,
		felixWriter:     toDriver,
	}
	return felixConn
}

func (fc *DataplaneConn) readMessagesFromDataplane() {
	defer func() {
		fc.failed <- true
	}()
	glog.Info("Reading from dataplane driver pipe...")
	for {
		buf := make([]byte, 8)
		_, err := io.ReadFull(fc.felixReader, buf)
		if err != nil {
			glog.Fatalf("Failed to read from front-end socket: %v", err)
		}
		length := binary.LittleEndian.Uint64(buf)

		data := make([]byte, length)
		_, err = io.ReadFull(fc.felixReader, data)
		if err != nil {
			glog.Fatalf("Failed to read from front-end socket: %v", err)
		}

		msg := proto.FromDataplane{}
		pb.Unmarshal(data, &msg)

		glog.V(3).Infof("Message from Felix: %#v", msg.Payload)

		payload := msg.Payload
		switch msg := payload.(type) {
		case *proto.FromDataplane_ProcessStatusUpdate:
			fc.handleProcessStatusUpdate(msg.ProcessStatusUpdate)
		case *proto.FromDataplane_WorkloadEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.WorkloadEndpointStatusUpdate
			}
		case *proto.FromDataplane_WorkloadEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.WorkloadEndpointStatusRemove
			}
		case *proto.FromDataplane_HostEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.HostEndpointStatusUpdate
			}
		case *proto.FromDataplane_HostEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.HostEndpointStatusRemove
			}
		default:
			glog.Warningf("XXXX Unknown message from felix: %#v", msg)
		}
		glog.V(3).Info("Finished handling message from front-end")
	}
}

func (fc *DataplaneConn) handleProcessStatusUpdate(msg *proto.ProcessStatusUpdate) {
	glog.V(3).Infof("Status update from dataplane driver: %v", *msg)
	statusReport := model.StatusReport{
		Timestamp:     msg.IsoTimestamp,
		UptimeSeconds: msg.Uptime,
		FirstUpdate:   !fc.firstStatusReportSent,
	}
	kv := model.KVPair{
		Key:   model.ActiveStatusReportKey{Hostname: fc.config.FelixHostname},
		Value: &statusReport,
		// BUG(smc) Should honour TTL config
		TTL: 90 * time.Second,
	}
	_, err := fc.datastore.Apply(&kv)
	if err != nil {
		glog.Warningf("Failed to write status to datastore: %v", err)
	} else {
		fc.firstStatusReportSent = true
	}
	kv = model.KVPair{
		Key:   model.LastStatusReportKey{Hostname: fc.config.FelixHostname},
		Value: &statusReport,
	}
	_, err = fc.datastore.Apply(&kv)
	if err != nil {
		glog.Warningf("Failed to write status to datastore: %v", err)
	}
}

func (fc *DataplaneConn) sendMessagesToDataplaneDriver() {
	defer func() {
		fc.failed <- true
	}()
	for {
		msg := <-fc.toFelix

		switch msg.(type) {
		case *proto.InSync:
			if !fc.datastoreInSync {
				fc.datastoreInSync = true
				fc.inSync <- true
			}
		}

		fc.marshalToDataplane(msg)
	}
}

func (fc *DataplaneConn) marshalToDataplane(msg interface{}) {
	glog.V(3).Infof("Writing msg (%v) to felix: %#v\n", fc.nextSeqNumber, msg)

	envelope := &proto.ToDataplane{
		SequenceNumber: fc.nextSeqNumber,
	}
	fc.nextSeqNumber += 1
	switch msg := msg.(type) {
	case *proto.ConfigUpdate:
		envelope.Payload = &proto.ToDataplane_ConfigUpdate{msg}
	case *proto.InSync:
		envelope.Payload = &proto.ToDataplane_InSync{msg}
	case *proto.IPSetUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetUpdate{msg}
	case *proto.IPSetDeltaUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetDeltaUpdate{msg}
	case *proto.IPSetRemove:
		envelope.Payload = &proto.ToDataplane_IpsetRemove{msg}
	case *proto.ActivePolicyUpdate:
		envelope.Payload = &proto.ToDataplane_ActivePolicyUpdate{msg}
	case *proto.ActivePolicyRemove:
		envelope.Payload = &proto.ToDataplane_ActivePolicyRemove{msg}
	case *proto.ActiveProfileUpdate:
		envelope.Payload = &proto.ToDataplane_ActiveProfileUpdate{msg}
	case *proto.ActiveProfileRemove:
		envelope.Payload = &proto.ToDataplane_ActiveProfileRemove{msg}
	case *proto.HostEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_HostEndpointUpdate{msg}
	case *proto.HostEndpointRemove:
		envelope.Payload = &proto.ToDataplane_HostEndpointRemove{msg}
	case *proto.WorkloadEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointUpdate{msg}
	case *proto.WorkloadEndpointRemove:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointRemove{msg}
	default:
		glog.Fatalf("Unknown message type: %#v", msg)
	}
	//
	//if glog.V(4) {
	//	// For debugging purposes, dump the message to
	//	// messagepack; parse it as a map and dump it to JSON.
	//	bs := make([]byte, 0)
	//	enc := codec.NewEncoderBytes(&bs, msgpackHandle)
	//	enc.Encode(envelope)
	//
	//	dec := codec.NewDecoderBytes(bs, msgpackHandle)
	//	var decodedType string
	//	msgAsMap := make(map[string]interface{})
	//	dec.Decode(&decodedType)
	//	dec.Decode(msgAsMap)
	//	jsonMsg, err := json.Marshal(msgAsMap)
	//	if err == nil {
	//		glog.Infof("Dumped message: %v %v", decodedType, string(jsonMsg))
	//	} else {
	//		glog.Infof("Failed to dump map to JSON: (%v) %v", err, msgAsMap)
	//	}
	//}
	data, err := pb.Marshal(envelope)
	if err != nil {
		glog.Fatalf("Failed to marshal data to front end: %#v; %v",
			msg, err)
	}

	lengthBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBuffer, uint64(len(data)))

	numBytes, err := fc.felixWriter.Write(lengthBuffer)
	if err != nil || numBytes != len(lengthBuffer) {
		glog.Fatalf("Failed to write to front end (only wrote %v bytes): %v",
			numBytes, err)
	}
	numBytes, err = fc.felixWriter.Write(data)
	if err != nil || numBytes != len(data) {
		glog.Fatalf("Failed to write to front end (only wrote %v bytes): %v",
			numBytes, err)
	}
}

func (fc *DataplaneConn) Start() {
	// Start a background thread to write to the dataplane driver.
	go fc.sendMessagesToDataplaneDriver()

	// Send the opening message to the dataplane driver, giving it its
	// config.
	fc.toFelix <- &proto.ConfigUpdate{
		Config: fc.config.RawValues,
	}

	// Start background thread to read messages from dataplane driver.
	go fc.readMessagesFromDataplane()

	// Create the ipsets/active policy calculation graph, which will
	// do the dynamic calculation of ipset memberships and active policies
	// etc.
	asyncCalcGraph := calc.NewAsyncCalcGraph(fc.config, fc.toFelix)

	// Create the datastore syncer, which will feed the calculation graph.
	syncer := fc.datastore.Syncer(asyncCalcGraph)
	glog.V(3).Infof("Created Syncer: %#v", syncer)

	// Start the background processing threads.
	glog.V(2).Infof("Starting the datastore Syncer/processing graph")
	syncer.Start()
	asyncCalcGraph.Start()
	glog.V(2).Infof("Started the datastore Syncer/processing graph")

	if fc.config.EndpointReportingEnabled {
		glog.V(1).Info("Endpoint status reporting enabled, starting status reporter")
		fc.statusReporter = status.NewEndpointStatusReporter(
			fc.config.FelixHostname,
			fc.endpointUpdates,
			fc.inSync,
			fc.datastore,
			fc.config.EndpointReportingDelay(),
			fc.config.EndpointReportingDelay()*180,
		)
		fc.statusReporter.Start()
	}
}

func (fc *DataplaneConn) Join() {
	_ = <-fc.failed
	glog.Fatal("Background thread failed")
}
