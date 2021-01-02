package wireguard

type Config struct {
	// Wireguard configuration
	Enabled                    bool
	WireguardRoutingMode       string
	ListeningPort              int
	MarkDoNotRouteViaWireguard int
	MarkNonCaliWorkloadIface   int
	RoutingRulePriority        int
	NodeRoutingTableIndex      int
	WorkloadRoutingTableIndex  int
	InterfaceName              string
	MTU                        int
}
