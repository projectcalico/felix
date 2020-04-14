package mock

import (
	"net"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/libcalico-go/lib/set"
	wireguardshim "github.com/projectcalico/felix/shims/wireguard"
)

func NewMockWireguard() *MockWireguard {
	return &MockWireguard{
		nameToLink:       map[string]netlink.Link{},
		RouteKeyToRoute:  map[string]netlink.Route{},
		AddedRouteKeys:   set.New(),
		DeletedRouteKeys: set.New(),
		UpdatedRouteKeys: set.New(),
	}
}

var _ wireguardshim.Wireguard = NewMockWireguard()

type MockWireguard struct {
	nameToLink map[string]netlink.Link

	RouteKeyToRoute  map[string]netlink.Route
	AddedRouteKeys   set.Set
	DeletedRouteKeys set.Set
	UpdatedRouteKeys set.Set

	NumNewNetlinkCalls int
	NetlinkOpen        bool

	PersistentlyFailToConnect bool

	PersistFailures    bool
	FailuresToSimulate FailFlags

	mutex                   sync.Mutex
	deletedConntrackEntries []net.IP
	ConntrackSleep          time.Duration
}

func (d *MockWireguard) AddIface(idx int, name string, up bool, running bool) *MockLink {
	flags := net.Flags(0)
	var rawFlags uint32
	if up {
		flags |= net.FlagUp
		rawFlags |= syscall.IFF_UP
	}
	if running {
		rawFlags |= syscall.IFF_RUNNING
	}
	link := &MockLink{
		LinkAttrs: netlink.LinkAttrs{
			Name:     name,
			Flags:    flags,
			RawFlags: rawFlags,
			Index:    idx,
		},
	}
	d.nameToLink[name] = link
	return link
}

func (d *MockWireguard) shouldFail(flag FailFlags) bool {
	flagPresent := d.FailuresToSimulate&flag != 0
	if !d.PersistFailures {
		d.FailuresToSimulate &^= flag
	}
	if flagPresent {
		log.WithField("flag", flag).Warn("Mock dataplane: triggering failure")
	}
	return flagPresent
}

func (d *MockWireguard) NewWireguardClient() (*MockWireguard, error) {
	d.NumNewNetlinkCalls++
	if d.PersistentlyFailToConnect || d.shouldFail(FailNextNewNetlinkHandle) {
		return nil, SimulatedError
	}
	Expect(d.NetlinkOpen).To(BeFalse())
	d.NetlinkOpen = true
	return d, nil
}

func (d *MockWireguard) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	d.NetlinkOpen = false
	if d.shouldFail(FailNextClose) {
		return SimulatedError
	}

	return nil
}

func (d *MockWireguard) DeviceByName(name string) (*wgtypes.Device, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextWireguardDeviceByName) {
		return nil, SimulatedError
	}

	return nil, nil
}

func (d *MockWireguard) ConfigureDevice(name string, cfg wgtypes.Config) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	Expect(d.NetlinkOpen).To(BeTrue())
	if d.shouldFail(FailNextConfigureWireguardDevice) {
		return SimulatedError
	}

	return nil
}
