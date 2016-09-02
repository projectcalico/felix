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

// The proto package defines the protocol between the front-end and back-end.
//
// Overview
//
// The front-end creates a server socket and accepts the connection from the
// backend.
//
// The protocol (described in more detail below) starts with a handshake to
// exchange configuration.  Then the back-end begins its resync with the
// datastore, emitting updates as it scans through the current state.
// Once complete, the back-end enters the "in-sync" state and starts sending
// only updates.  The front-end may send  process/endpoint status updates at
// any time after the handshake.
//
// The wire-format for the protocol uses messagepack.  It is described in
// more detail below.
//
// Handshake
//
// The protocol starts with handshake messages.  The front-end sends an Init
// message with the datastore connection config.  Then, the back-end loads
// additional raw config from the datastore and returns it in a ConfigUpdate
// message. Finally, the front-end parses and resolves the raw config and
// responds with the "final" config in a ConfigResolved message.
//
// Resync and updates
//
// After the handshake, the back-end enters enters the "resync" state,
// during which it both: scans through the complete state of the datastore,
// and, processes update events from the datastore as they come in.  When it
// detects an active resource, whether in the datastore scan or the stream of
// updates from the datastore, it sends an <Type>Update message to the
// frontend (or a <Type>Remove for a deletion).
//
// Note: if there are concurrent updates to the datastore during the resync,
// the back-end will send an eventually-consistent stream of events.  For
// example, if an object in the datamodel exists in the datastore at the
// start of the resync but then it is deleted while the resync is in progress,
// the back-end may send an update for the resource then a delete, or, it may
// skip the resource entirely. (But it will not send a Remove then an Update
// because that would leave the front-end in the incorrect state.)
//
// For simplicity and robustness, <Type>Update messages contain the complete
// current state of the resource that they refer to.  However, for
// performance, IP set updates are communicated as an initial IPSetUpdate,
// followed by a sequence of IPSetDeltaUpdate messages.
//
// Once all of the pre-existing data has been sent, the back-end enters the
// "in-sync" state and starts sending only updates.
//
// If it loses sync with the datastore and has to do another scan, it
// re-enters the "resync" state.
//
// Special cases
//
// If the back-end fails to parse an update from the datastore, it simulates
// a deletion for the relevant resource.  As such the front-end must be robust
// to duplicate Remove messages as well as receiving a Remove message for a
// resource that it hadn't previously been told about.
//
// The above also implies that the front-end needs to be robust against
// receiving partial information.  For example,. if it receives an endpoint
// that refers to profile X but profile X is never sent or is deleted then it
// should handle that by dropping packets that would go to profile X.
//
// Illustration
//
// The protocol flow is illustrated below.
//
//	+-----------+                                  +---------+
//	| frontend  |                                  | backend |
//	+-----------+                                  +---------+
//	      |                                             |
//	      | **Create**                                  |
//	      |-------------------------------------------->|
//	      | ---------------------\                      |
//	      |-| Start of handshake |                      |
//	      | |--------------------|                      |
//	      |                                             |
//	      | Init(Hostname, etcd config)                 |
//	      |-------------------------------------------->|
//	      |                   ------------------------\ |
//	      |                   | Connects to datastore |-|
//	      |                   |-----------------------| |
//	      |                                             |
//	      |              ConfigUpdate(global, per-host) |
//	      |<--------------------------------------------|
//	      |                                             |
//	      | ConfigResolved(logging config)              |
//	      |-------------------------------------------->|
//	      |                        -------------------\ |
//	      |                        | End of handshake |-|
//	      |                        |------------------| |
//	      |                                             |
//	      |           DatastoreStatus("wait-for-ready") |
//	      |<--------------------------------------------|
//	      |         ----------------------------------\ |
//	      |         | Starts  resync, sending updates |-|
//	      |         |---------------------------------| |
//	      |                                             |
//	      |                   DatastoreStatus("resync") |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |            IPSet(Update|DeltaUpdate|Remove) |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |       Active(Profile|Policy)(Update|Remove) |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |      (Workload|Host)Endpoint(Update|Remove) |
//	      |<--------------------------------------------|
//	      |                           ----------------\ |
//	      |                           | Finishes sync |-|
//	      |                           |---------------| |
//	      |                                             |
//	      |              ConfigUpdate(global, per-host) |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |                  DatastoreStatus("in-sync") |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |            IPSet(Update|DeltaUpdate|Remove) |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |       Active(Profile|Policy)(Update|Remove) |
//	      |<--------------------------------------------|
//	      |                                             |
//	      |      (Workload|Host)Endpoint(Update|Remove) |
//	      |<--------------------------------------------|
//	      | ------------------------------------\       |
//	      |-| Status updates (sent at any time) |       |
//	      | |-----------------------------------|       |
//	      |                                             |
//	      | FelixStatusUpdate                           |
//	      |-------------------------------------------->|
//	      |                                             |
//	      | (Workload|Host)EndpointStatus               |
//	      |-------------------------------------------->|
//	      |                                             |
//
// Wire format
//
// The protocol between the front-end and back-end is message-pack based.
// On the wire, each message consists fo two messagepack objects.  The first
// is a string identifying the type of message.  The second is the body of the
// message, which is a dict.
//
// To simplify encoding/decoding messages into structs, this package provides
// the Envelope struct.  The Envelope struct contains a Payload field to hold
// a pointer to one of the message body structs.  When marshaled, it maps the
// type of the payload to the correct type name and vice-versa:
//
// 	// Encoding:
// 	msg := DatastoreStatus{Status: "resync"}
// 	envelope := Envelope{Payload:&msg}
// 	encoder.Encode(envelope)
// 	... encodes "datastore_status" {"status": "resync"}
//
// 	// Decoding:
// 	envelope := Envelope{}
// 	decoder.decode(&envelope)
// 	... envelope.Payload is now a DatastoreStatus{}
package proto

// http://textart.io/sequence Source code for sequence diagram above:

var _ = `
object frontend backend
frontend->backend: **Create**
note right of frontend: Start of handshake
frontend->backend: Init(Hostname, etcd config)
note left of backend: Connects to datastore
backend->frontend: ConfigUpdate(global, per-host)
frontend->backend: ConfigResolved(logging config)
note left of backend: End of handshake

backend->frontend: DatastoreStatus("wait-for-ready")
note left of backend: Starts  resync, sending updates
backend->frontend: DatastoreStatus("resync")

backend->frontend: IPSet(Update|DeltaUpdate|Remove)
backend->frontend: Active(Profile|Policy)(Update|Remove)
backend->frontend: (Workload|Host)Endpoint(Update|Remove)

note left of backend: Finishes sync
backend->frontend: ConfigUpdate(global, per-host)
backend->frontend: DatastoreStatus("in-sync")

backend->frontend: IPSet(Update|DeltaUpdate|Remove)
backend->frontend: Active(Profile|Policy)(Update|Remove)
backend->frontend: (Workload|Host)Endpoint(Update|Remove)

note right of frontend: Status updates (sent at any time)
frontend->backend: FelixStatusUpdate
frontend->backend: (Workload|Host)EndpointStatus
`
