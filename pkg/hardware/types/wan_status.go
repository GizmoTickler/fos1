package types

// WANStatus represents the status of a WAN interface
type WANStatus struct {
	// Name is the name of the interface
	Name string

	// State is the current state of the interface (up, down, degraded, etc.)
	State string

	// LastStateChange is the timestamp of the last state change
	LastStateChange string

	// Active indicates whether this is the active WAN interface
	Active bool

	// Latency is the current latency in milliseconds
	Latency int

	// PacketLoss is the current packet loss percentage
	PacketLoss float64

	// Jitter is the current jitter in milliseconds
	Jitter int

	// Uptime is the uptime in seconds
	Uptime int64

	// BytesReceived is the number of bytes received
	BytesReceived uint64

	// BytesSent is the number of bytes sent
	BytesSent uint64

	// PacketsReceived is the number of packets received
	PacketsReceived uint64

	// PacketsSent is the number of packets sent
	PacketsSent uint64
}

// WANInterfaceStatus represents the status of a WAN interface
type WANInterfaceStatus struct {
	// Name is the name of the interface
	Name string

	// State is the current state of the interface
	State string

	// LastStateChange is the timestamp of the last state change
	LastStateChange string

	// Active indicates whether this is the active WAN interface
	Active bool
}


