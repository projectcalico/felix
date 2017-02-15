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
	"time"

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

type testSyncer struct {
	callbacks bapi.SyncerCallbacks
	datastore *testDatastore
	tracker   map[string]model.Key
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
	switch object.Key.(type) {
	case model.ActiveStatusReportKey:
		// Don't store this, just return it.
		return object, nil
	case model.LastStatusReportKey:
		// Don't store this, just return it.
		return object, nil
	}
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
	switch key.(type) {
	case model.ReadyFlagKey:
		return &model.KVPair{Key: key, Value: true}, nil
	}
	return nil, errors.New("Not implemented yet")
}

// List returns a slice of KVPairs matching the input list options.
// list should be passed one of the model.<Type>ListOptions structs.
// Non-zero fields in the struct are used as filters.
func (d *testDatastore) List(list model.ListInterface) ([]*model.KVPair, error) {
	log.WithField("list", list).Debug("FV:List")
	switch list.(type) {
	case model.GlobalConfigListOptions:
		return []*model.KVPair{}, nil
	case model.HostConfigListOptions:
		return []*model.KVPair{}, nil
	}
	return nil, errors.New("Not implemented yet")
}

// Syncer creates an object that generates a series of KVPair updates,
// which paint an eventually-consistent picture of the full state of
// the datastore and then generates subsequent KVPair updates for
// changes to the datastore.
func (d *testDatastore) Syncer(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	log.WithField("callbacks", callbacks).Debug("FV:Syncer")
	syn := &testSyncer{
		callbacks: callbacks,
		datastore: d,
		tracker:   map[string]model.Key{},
	}
	return syn
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
func (syn *testSyncer) Start() {
	log.Debug("FV:Start")
	go syn.syncer()
	return
}

func (syn *testSyncer) syncer() {
	log.Debug("FV:syncer")
	time.Sleep(5 * time.Second)
	syn.sendUpdates([]model.KVPair{{
		Key:   model.ReadyFlagKey{},
		Value: true,
	}})
	syn.callbacks.OnStatusUpdated(bapi.InSync)
	for {
		time.Sleep(1 * time.Second)
	}
	return
}

// sendUpdates sends updates to the callback and updates the resource
// tracker.
func (syn *testSyncer) sendUpdates(kvps []model.KVPair) {
	updates := syn.convertKVPairsToUpdates(kvps)

	// Send to the callback and update the tracker.
	syn.callbacks.OnUpdates(updates)
	syn.updateTracker(updates)
}

// convertKVPairsToUpdates converts a list of KVPairs to the list
// of api.Update objects which should be sent to OnUpdates.  It filters out
// deletes for any KVPairs which we don't know about.
func (syn *testSyncer) convertKVPairsToUpdates(kvps []model.KVPair) []bapi.Update {
	updates := []bapi.Update{}
	for _, kvp := range kvps {
		if _, ok := syn.tracker[kvp.Key.String()]; !ok && kvp.Value == nil {
			// The given KVPair is not in the tracker, and is a delete, so no need to
			// send a delete update.
			continue
		}
		updates = append(updates, bapi.Update{KVPair: kvp, UpdateType: syn.getUpdateType(kvp)})
	}
	return updates
}

// updateTracker updates the global object tracker with the given update.
// updateTracker should be called after sending a update to the OnUpdates callback.
func (syn *testSyncer) updateTracker(updates []bapi.Update) {
	for _, upd := range updates {
		if upd.UpdateType == bapi.UpdateTypeKVDeleted {
			log.Debugf("Delete from tracker: %+v", upd.KVPair.Key)
			delete(syn.tracker, upd.KVPair.Key.String())
		} else {
			log.Debugf("Update tracker: %+v: %+v", upd.KVPair.Key, upd.KVPair.Revision)
			syn.tracker[upd.KVPair.Key.String()] = upd.KVPair.Key
		}
	}
}

func (syn *testSyncer) getUpdateType(kvp model.KVPair) bapi.UpdateType {
	if kvp.Value == nil {
		// If the value is nil, then this is a delete.
		return bapi.UpdateTypeKVDeleted
	}

	// Not a delete.
	if _, ok := syn.tracker[kvp.Key.String()]; !ok {
		// If not a delete and it does not exist in the tracker, this is an add.
		return bapi.UpdateTypeKVNew
	} else {
		// If not a delete and it exists in the tracker, this is an update.
		return bapi.UpdateTypeKVUpdated
	}
}
