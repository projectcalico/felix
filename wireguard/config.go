package wireguard

type Config struct {
	// Wireguard configuration
	Enabled                   bool
	ListeningPort             int
	FirewallMark              int
	RoutingRulePriority       int
	NodeRoutingTableIndex     int
	WorkloadRoutingTableIndex int
	InterfaceName             string
	MTU                       int
}
