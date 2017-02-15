// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package fv

// This 'fv' package contains test code that is useful for testing the whole of Felix, including
// real dataplane programming.

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/api"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/compat"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

func NewTestDatastore(config api.CalicoAPIConfig) (c bapi.Client, err error) {
	log.Info("Using FV test datastore")
	c = compat.NewAdaptor(&testDatastore{})
	err = nil
	return
}

type testDatastore struct {
}

// Create creates the object specified in the KVPair, which must not
// already exist. On success, returns a KVPair for the object with
// revision  information filled-in.
func (d *testDatastore) Create(object *model.KVPair) (*model.KVPair, error) {
	log.WithField("object", object).Debug("FV:Create")
	return nil, errors.New("Not implemented yet")
}

// Update modifies the existing object specified in the KVPair.
// On success, returns a KVPair for the object with revision
// information filled-in.  If the input KVPair has revision
// information then the update only succeeds if the revision is still
// current.
func (d *testDatastore) Update(object *model.KVPair) (*model.KVPair, error) {
	log.WithField("object", object).Debug("FV:Update")
	return nil, errors.New("Not implemented yet")
}

// Apply updates or creates the object specified in the KVPair.
// On success, returns a KVPair for the object with revision
// information filled-in.  If the input KVPair has revision
// information then the update only succeeds if the revision is still
// current.
func (d *testDatastore) Apply(object *model.KVPair) (*model.KVPair, error) {
	log.WithField("object", object).Debug("FV:Apply")
	return nil, errors.New("Not implemented yet")
}

// Delete removes the object specified by the KVPair.  If the KVPair
// contains revision information, the delete only succeeds if the
// revision is still current.
//
// Some keys are hierarchical, and Delete is a recursive operation.
//
// Any objects that were implicitly added by a Create operation should
// also be removed when deleting the objects that implicitly created it.
// For example, deleting the last WorkloadEndpoint in a Workload will
// also remove the Workload.
func (d *testDatastore) Delete(object *model.KVPair) error {
	log.WithField("object", object).Debug("FV:Delete")
	return errors.New("Not implemented yet")
}

// Get returns the object identified by the given key as a KVPair with
// revision information.
func (d *testDatastore) Get(key model.Key) (*model.KVPair, error) {
	log.WithField("key", key).Debug("FV:Get")
	return nil, errors.New("Not implemented yet")
}

// List returns a slice of KVPairs matching the input list options.
// list should be passed one of the model.<Type>ListOptions structs.
// Non-zero fields in the struct are used as filters.
func (d *testDatastore) List(list model.ListInterface) ([]*model.KVPair, error) {
	log.WithField("list", list).Debug("FV:List")
	return nil, errors.New("Not implemented yet")
}

// Syncer creates an object that generates a series of KVPair updates,
// which paint an eventually-consistent picture of the full state of
// the datastore and then generates subsequent KVPair updates for
// changes to the datastore.
func (d *testDatastore) Syncer(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	log.WithField("callbacks", callbacks).Debug("FV:Syncer")
	return d
}

// EnsureInitialized ensures that the backend is initialized
// any ready to be used.
func (d *testDatastore) EnsureInitialized() error {
	log.Debug("FV:EnsureInitialized")
	return errors.New("Not implemented yet")
}

// Perform any "backdoor" initialization required by the components
// used in calico/node.  This is a temporary mechanism and will be
// removed.
func (d *testDatastore) EnsureCalicoNodeInitialized(node string) error {
	log.WithField("node", node).Debug("FV:EnsureCalicoNodeInitialized")
	return errors.New("Not implemented yet")
}

// Starts the Syncer.  May start a background goroutine.
func (d *testDatastore) Start() {
	log.Debug("FV:Start")
	return
}
