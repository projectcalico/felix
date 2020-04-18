package mock

import (
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	netlinkshim "github.com/projectcalico/felix/netlink"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// ----- Mock dataplane management functions for test code -----

func (d *MockNetlinkDataplane) NewMockWireguard() (netlinkshim.Wireguard, error) {
	d.NumNewNetlinkCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(FailNextNewWireguard) {
		return nil, SimulatedError
	}
	if d.shouldFail(FailNextNewWireguardNotSupported) {
		return nil, NotSupportedError
	}
	Expect(d.NetlinkOpen).To(BeFalse())
	d.WireguardOpen = true
	return d, nil
}

// ----- Wireguard API -----

func (d *MockNetlinkDataplane) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.WireguardOpen).To(BeTrue())
	d.WireguardOpen = false
	if d.shouldFail(FailNextWireguardClose) {
		return SimulatedError
	}

	return nil
}

func (d *MockNetlinkDataplane) DeviceByName(name string) (*wgtypes.Device, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.WireguardOpen).To(BeTrue())
	if d.shouldFail(FailNextWireguardDeviceByName) {
		return nil, SimulatedError
	}
	link, ok := d.nameToLink[name]
	if !ok {
		return nil, NotFoundError
	}
	if link.Type() != "wireguard" {
		return nil, FileDoesNotExistError
	}

	device := &wgtypes.Device{
		Name:         name,
		Type:         wgtypes.LinuxKernel,
		PrivateKey:   link.wireguardPrivateKey,
		PublicKey:    link.wireguardPublicKey,
		ListenPort:   link.wireguardListenPort,
		FirewallMark: link.wireguardFirewallMark,
	}
	for _, peer := range link.wireguardPeers {
		device.Peers = append(device.Peers, peer)
	}

	return device, nil
}

func (d *MockNetlinkDataplane) ConfigureDevice(name string, cfg wgtypes.Config) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.WireguardOpen).To(BeTrue())
	if d.shouldFail(FailNextWireguardConfigureDevice) {
		return SimulatedError
	}
	link, ok := d.nameToLink[name]
	if !ok {
		return NotFoundError
	}

	if cfg.FirewallMark != nil {
		link.wireguardFirewallMark = *cfg.FirewallMark
	}
	if cfg.ListenPort != nil {
		link.wireguardListenPort = *cfg.ListenPort
	}
	if cfg.PrivateKey != nil {
		link.wireguardPrivateKey = *cfg.PrivateKey
		link.wireguardPublicKey = link.wireguardPrivateKey.PublicKey()
	}
	if cfg.ReplacePeers == true || len(cfg.Peers) > 0 {
		existing := link.wireguardPeers
		if cfg.ReplacePeers || link.wireguardPeers == nil {
			link.wireguardPeers = map[wgtypes.Key]wgtypes.Peer{}
		}
		for _, peerCfg := range cfg.Peers {
			Expect(peerCfg.PublicKey).NotTo(Equal(wgtypes.Key{}))
			if peerCfg.UpdateOnly {
				if _, ok := existing[peerCfg.PublicKey]; !ok {
					return NotFoundError
				}
			}
			if peerCfg.Remove {
				if _, ok := existing[peerCfg.PublicKey]; !ok {
					return NotFoundError
				}
				delete(existing, peerCfg.PublicKey)
				continue
			}
			peer := link.wireguardPeers[peerCfg.PublicKey]
			if peerCfg.Endpoint != nil {
				peer.Endpoint = peerCfg.Endpoint
			}
			if peerCfg.PersistentKeepaliveInterval != nil {
				peer.PersistentKeepaliveInterval = *peerCfg.PersistentKeepaliveInterval
			}
			allowedIPs := set.New()
			if !peerCfg.ReplaceAllowedIPs && len(peer.AllowedIPs) > 0 {
				allowedIPs.AddAll(peer.AllowedIPs)
			}
			if len(peerCfg.AllowedIPs) > 0 {
				allowedIPs.AddAll(peerCfg.AllowedIPs)
			}
		}
	}

	return nil
}
