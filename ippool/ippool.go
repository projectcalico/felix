// Copyright (c) 2017 Tigera, Inc. All rights reserved.
// Copyright (C) 2017 VA Linux Systems Japan K.K.
// Copyright (C) 2017 Fumihiko Kakuma <kakuma at valinux co jp>
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package ippool

import (
	"errors"
	"os/exec"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	"golang.org/x/net/context"

	"github.com/projectcalico/felix/config"
	capi "github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

const (
	CLIENT_TIMEOUT = 30 * time.Second
)

type Watcher struct {
	config *config.Config
	client etcd.KeysAPI
}

func (w *Watcher) Watcher() {
	go w.watchIPPool()
}

func (w *Watcher) watchIPPool() error {
	var lastindex uint64

	log.Info("ippool watcher started.")
	ippoollistopts := model.IPPoolListOptions{}
	dir := model.ListOptionsToDefaultPathRoot(ippoollistopts)
	resp, err := w.client.Get(context.Background(), dir, &etcd.GetOptions{Quorum: true})
	if err != nil {
		log.Errorf("Failed to get %s.", dir)
		return err
	}
	lastindex = resp.Index
	log.Debugf("Get index %d for %s", lastindex, dir)
	if err := allocateIpip(); err != nil {
		log.Error("Failed to execute allocate-ipip-addr.")
		return err
	}
	for {
		watcher := w.client.Watcher(dir, &etcd.WatcherOptions{AfterIndex: lastindex, Recursive: true})
		resp, err := watcher.Next(context.Background())
		if err != nil {
			log.Errorf("Failed to watch %s.", dir)
			return err
		}
		lastindex = resp.Node.ModifiedIndex
		log.Debugf("Watched %s action for %s with index %d", resp.Action, dir, lastindex)
		if err := allocateIpip(); err != nil {
			log.Error("Failed to execute allocate-ipip-addr.")
			return err
		}
	}
}

func allocateIpip() error {
	cmd := exec.Command("/bin/sh", "-c", "allocate-ipip-addr")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func NewWatcher(configParams *config.Config) (*Watcher, error) {
	var err error
	if configParams.NetworkingBackend != "gobgp" {
		return nil, err
	}
	if configParams.DatastoreType != "etcdv2" {
		return nil, err
	}
	datastoreConfig := configParams.DatastoreConfig()
	etcdKeysAPI, err := newEtcdClient(&datastoreConfig.Spec.EtcdConfig)
	if err != nil {
		log.Error("Failed to get etcd cliant.")
		return nil, err
	}
	w := &Watcher{
		config: configParams,
		client: etcdKeysAPI,
	}
	log.Debug("Get new watcher")
	return w, err
}

func newEtcdClient(config *capi.EtcdConfig) (etcd.KeysAPI, error) {
	etcdLocation := []string{}
	if config.EtcdAuthority != "" {
		etcdLocation = []string{config.EtcdScheme + "://" + config.EtcdAuthority}
	}
	if config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.EtcdEndpoints, ",")
	}

	if len(etcdLocation) == 0 {
		return nil, errors.New("no etcd authority or endpoints specified")
	}

	// Create the etcd client
	tls := transport.TLSInfo{
		CAFile:   config.EtcdCACertFile,
		CertFile: config.EtcdCertFile,
		KeyFile:  config.EtcdKeyFile,
	}
	transport, err := transport.NewTransport(tls, CLIENT_TIMEOUT)
	if err != nil {
		return nil, err
	}

	cfg := etcd.Config{
		Endpoints:               etcdLocation,
		Transport:               transport,
		HeaderTimeoutPerRequest: CLIENT_TIMEOUT,
	}

	// Plumb through the username and password if both are configured.
	if config.EtcdUsername != "" && config.EtcdPassword != "" {
		cfg.Username = config.EtcdUsername
		cfg.Password = config.EtcdPassword
	}

	client, err := etcd.New(cfg)
	if err != nil {
		return nil, err
	}
	etcdKeysAPI := etcd.NewKeysAPI(client)

	return etcdKeysAPI, nil
}
