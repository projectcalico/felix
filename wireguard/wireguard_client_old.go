// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// The ip package contains yet another IP address (and CIDR) type :-).   The
// types differ from the ones in the net package in that they are backed by
// fixed-sized arrays of the appropriate size.  The key advantage of
// using a fixed-size array is that it makes the types hashable so they can
// be used as map keys.  In addition, they can be converted to net.IP by
// slicing.
/*
package wireguard

import (
	"fmt"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type WireguardShim interface {
	// Setup Wireguard device and return public-key.
	Setup() (string, error)
	// Updated Wireguard device settings.
	Update() error
	// Add a remote peer configuration.
	AddPeer(string, string, []string) error
	// Update remote peer configuration.
	UpdatePeer(string, string, []string) error
	// Remove remote peer.
	RemovePeer(string) error
	// Close() releases resources associated with this client.
	Close()
	EnsureInterface() (wgtypes.Key, error)
}

func NewWireguardDeviceManager(name string, enabled bool, mtu *int, fwMark int,
	port int) (*WireguardClient, error) {
	// setup WG config session.
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &WireguardClient{
		Client: client,
		IfName: name,
		Mtu:    mtu,
		FwMark: fwMark,
		ListeningPort:   port,
	}, nil
}

func (wgc *WireguardClient) Close() error {
	return wgc.Client.Close()
}

func (wgc *WireguardClient) EnsureInterface() (*wgtypes.Device, error) {
	link, err := netlink.LinkByName(wgc.IfName)
	if os.IsNotExist(err) {
		err := wgc.createWireguardLink()

		attr := netlink.NewLinkAttrs()
		attr.Name = wgc.IfName
		lwg := netlink.GenericLink{
			LinkAttrs: attr,
			LinkType: wireguardType,
		}

		if err := netlink.LinkAdd(&lwg); err != nil {
			log.Errorf("error adding wireguard type link: %v", err)
			return err
		}

		link, err = netlink.LinkByName(wgc.IfName)
		if err != nil {
			log.Errorf("error adding wireguard type link: %v", err)
			return err
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("error setting link up: %v", err)
		return err
	}


	if err != nil {
		log.Errorf("wireguard link is missing: %v", err)
		return err
	}

	linkAttr := link.Attrs()
	if

	if err := netlink.LinkSetMTU(link, *wgc.Mtu); err != nil {
		log.Errorf("error updating wireguard type link: %v", err)
		return err
	}

	return nil
}

func (wgc *WireguardClient) EnsureWireguardConfig() (*wgtypes.Device, error) {
	device, err := wgc.Client.Device(wgc.IfName)

	// If wireguard support is not enabled then remove the wireguard device.
	if !wgc.Enabled {
		if os.IsNotExist(err) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		return nil, wgc.deleteWireguardLink()
	}

	// Wireguard is supported, ensure the device configuration is correct. This does not include peer information
	// which is handled elsewhere.
	if !os.IsNotExist(err) {
		// Wireguard device is not present, so
		err := wgc.createWireguardLink()
		if err != nil {
			log.Errorf("error creating wireguard device: %v", err)
			return nil, err
		}
	}

	// Determine if any configuration on the device needs updating
	update := wgtypes.Config{}
	updateRequired := false
	if device.FirewallMark != wgc.FwMark {
		update.FirewallMark = &wgc.FwMark
		updateRequired = true
	}
	if device.ListeningPort != wgc.ListeningPort {
		update.ListeningPort = &wgc.ListeningPort
		updateRequired = true
	}
	if device.PrivateKey == zeroKey || device.PublicKey == zeroKey {
		// One of the private or public key is not set. Generate a new private key and return the corresponding
		// public key.
		pkey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Errorf("error generating private-key: %v", err)
			return wgtypes.Key{}, err
		}
		update.PrivateKey = &pkey
		updateRequired = true
	}

	if updateRequired {
		// Update is required, so configure the device with the updated settings.
		err = wgc.Client.ConfigureDevice(*wgc.IfName, update)
		if err != nil {
			log.Errorf("error setting private-key: %v", err)
			return wgtypes.Key{}, err
		}
	}

	wgc.PubKey = pkey.PublicKey()
	return wgc.PubKey, nil
}

func (wgc *WireguardClient) Update() error {
	return wgc.updateWireguardLink()
}

func (wgc *WireguardClient) AddPeer(peerPubKey string,
	endpoint string,
	ipCIDRs []string) error {
	// setup WG config session.
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	var allowedIps []net.IPNet
	for _, ipCIDR := range ipCIDRs {
		_, ipNet, err := net.ParseCIDR(ipCIDR)
		if err == nil {
			continue
		}
		allowedIps = append(allowedIps, *ipNet)
	}

	pubKey, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return err
	}

	wgtc := wgtypes.Config{
		PrivateKey: &wgc.Key,
		ListeningPort:       wgc.ListeningPort,
		Peers: []wgtypes.PeerConfig{{
			PublicKey: pubKey,
			Endpoint: &net.UDPAddr{
				IP:   net.ParseIP(fmt.Sprintf("%s/32", endpoint)),
				Port: *wgc.ListeningPort, // fixed port number.
			},
			AllowedIPs: allowedIps,
		}},
	}

	err = client.ConfigureDevice(*wgc.IfName, wgtc)
	if err != nil {
		log.Errorf("error adding peer: %v", err)
		return err
	}

	return nil
}

func (wgc *WireguardClient) UpdatePeer(peerPubKey string,
	endpoint string,
	ipCIDRs []string) error {
	// setup WG config session.
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	var allowedIps []net.IPNet
	for _, ipCIDR := range ipCIDRs {
		_, ipNet, err := net.ParseCIDR(ipCIDR)
		if err == nil {
			continue
		}
		allowedIps = append(allowedIps, *ipNet)
	}

	pubKey, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return err
	}

	wgtc := wgtypes.Config{
		PrivateKey: &wgc.Key,
		ListeningPort:       wgc.ListeningPort,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  pubKey,
			UpdateOnly: true,
			Endpoint: &net.UDPAddr{
				IP:   net.ParseIP(fmt.Sprintf("%s/32", endpoint)),
				Port: *wgc.ListeningPort, // fixed port number.
			},
			AllowedIPs: allowedIps,
		}},
	}

	err = client.ConfigureDevice(*wgc.IfName, wgtc)
	if err != nil {
		log.Errorf("error adding peer: %v", err)
		return err
	}

	return nil
}

func (wgc *WireguardClient) RemovePeer(peerPubKey string) error {
	// setup WG config session.
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	pubKey, err := wgtypes.ParseKey(peerPubKey)
	if err != nil {
		return err
	}

	wgtc := wgtypes.Config{
		PrivateKey: &wgc.Key,
		ListeningPort:       wgc.ListeningPort,
		Peers: []wgtypes.PeerConfig{{
			PublicKey: pubKey,
			Remove:    true,
		}},
	}

	err = client.ConfigureDevice(*wgc.IfName, wgtc)
	if err != nil {
		log.Errorf("error adding peer: %v", err)
		return err
	}

	return nil
}

func (wgc *WireguardClient) Destroy() error {
	return wgc.deleteWireguardLink()
}

//
// Link Management
//

func (wgc *WireguardClient) createWireguardLink() error {

	return nil
}

func (wgc *WireguardClient) deleteWireguardLink() error {
	link, err := netlink.LinkByName(*wgc.IfName)
	if err != nil {
		log.Errorf("error adding wireguard type link: %v", err)
		return err
	}

	if err := netlink.LinkDel(link); err != nil {
		log.Errorf("error deleting wireguard type link: %v", err)
		return err
	}

	return nil
}

func (wgc *WireguardClient) ensureWireguardLink() error {
	link, err := netlink.LinkByName(wgc.IfName)
	if os.IsNotExist(err) {
		err := wgc.createWireguardLink()

		attr := netlink.NewLinkAttrs()
		attr.Name = wgc.IfName
		lwg := netlink.GenericLink{
			LinkAttrs: attr,
			LinkType: wireguardType,
		}

		if err := netlink.LinkAdd(&lwg); err != nil {
			log.Errorf("error adding wireguard type link: %v", err)
			return err
		}

		link, err = netlink.LinkByName(wgc.IfName)
		if err != nil {
			log.Errorf("error adding wireguard type link: %v", err)
			return err
		}
	}


	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("error setting link up: %v", err)
		return err
	}


	if err != nil {
		log.Errorf("wireguard link is missing: %v", err)
		return err
	}

	linkAttr := link.Attrs()
	if

	if err := netlink.LinkSetMTU(link, *wgc.Mtu); err != nil {
		log.Errorf("error updating wireguard type link: %v", err)
		return err
	}

	return nil
}
*/