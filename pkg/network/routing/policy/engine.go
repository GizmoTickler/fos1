package policy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// engine implements the policy matching engine
type engine struct {
}

// newEngine creates a new policy engine
func newEngine() *engine {
	return &engine{}
}

// matchesPolicy checks if a packet matches a policy
func (e *engine) matchesPolicy(packet PacketInfo, policy RoutingPolicy) bool {
	// Check source match
	if !e.matchesSource(packet, policy.Match.Source) {
		return false
	}

	// Check destination match
	if !e.matchesDestination(packet, policy.Match.Destination) {
		return false
	}

	// Check protocol match
	if !e.matchesProtocol(packet, policy.Match.Protocol) {
		return false
	}

	// Check port match
	if !e.matchesPorts(packet, policy.Match.Ports) {
		return false
	}

	// Check application match
	if !e.matchesApplications(packet, policy.Match.Applications) {
		return false
	}

	// Check traffic type match
	if !e.matchesTrafficType(packet, policy.Match.TrafficType) {
		return false
	}

	// Check time match
	if !e.matchesTime(policy.Match.Time) {
		return false
	}

	// All checks passed
	return true
}

// matchesSource checks if a packet matches the source criteria
func (e *engine) matchesSource(packet PacketInfo, source SourceMatch) bool {
	// If no source criteria, match all
	if len(source.Networks) == 0 && len(source.Interfaces) == 0 {
		return true
	}

	// Check source networks
	if len(source.Networks) > 0 {
		matched := false
		for _, network := range source.Networks {
			if e.ipInNetwork(packet.SourceIP, network) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check source interfaces
	if len(source.Interfaces) > 0 {
		matched := false
		for _, iface := range source.Interfaces {
			if packet.Interface == iface {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchesDestination checks if a packet matches the destination criteria
func (e *engine) matchesDestination(packet PacketInfo, destination DestinationMatch) bool {
	// If no destination criteria, match all
	if len(destination.Networks) == 0 {
		return true
	}

	// Check destination networks
	matched := false
	for _, network := range destination.Networks {
		if e.ipInNetwork(packet.DestinationIP, network) {
			matched = true
			break
		}
	}
	return matched
}

// matchesProtocol checks if a packet matches the protocol criteria
func (e *engine) matchesProtocol(packet PacketInfo, protocol string) bool {
	// If no protocol criteria or "all", match all
	if protocol == "" || protocol == "all" {
		return true
	}

	// Check protocol
	return strings.EqualFold(packet.Protocol, protocol)
}

// matchesPorts checks if a packet matches the port criteria
func (e *engine) matchesPorts(packet PacketInfo, ports []PortRange) bool {
	// If no port criteria, match all
	if len(ports) == 0 {
		return true
	}

	// Check if protocol is TCP or UDP
	if packet.Protocol != "tcp" && packet.Protocol != "udp" {
		return false
	}

	// Check port ranges
	for _, portRange := range ports {
		if packet.DestinationPort >= portRange.Start && packet.DestinationPort <= portRange.End {
			return true
		}
	}

	return false
}

// matchesApplications checks if a packet matches the application criteria
func (e *engine) matchesApplications(packet PacketInfo, applications []string) bool {
	// If no application criteria, match all
	if len(applications) == 0 {
		return true
	}

	// If no application information, no match
	if packet.Application == "" {
		return false
	}

	// Check applications
	for _, app := range applications {
		if strings.EqualFold(packet.Application, app) {
			return true
		}
	}

	return false
}

// matchesTrafficType checks if a packet matches the traffic type criteria
func (e *engine) matchesTrafficType(packet PacketInfo, trafficTypes []string) bool {
	// If no traffic type criteria, match all
	if len(trafficTypes) == 0 {
		return true
	}

	// If no traffic type information, no match
	if packet.TrafficType == "" {
		return false
	}

	// Check traffic types
	for _, trafficType := range trafficTypes {
		if strings.EqualFold(packet.TrafficType, trafficType) {
			return true
		}
	}

	return false
}

// matchesTime checks if the current time matches the time criteria
func (e *engine) matchesTime(timeMatch TimeMatch) bool {
	// If no time criteria, match all
	if len(timeMatch.DaysOfWeek) == 0 && len(timeMatch.TimeOfDay) == 0 {
		return true
	}

	// Get current time
	now := time.Now()

	// Check days of week
	if len(timeMatch.DaysOfWeek) > 0 {
		matched := false
		currentDay := strings.ToLower(now.Weekday().String())
		for _, day := range timeMatch.DaysOfWeek {
			if strings.EqualFold(currentDay, day) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check time of day
	if len(timeMatch.TimeOfDay) > 0 {
		matched := false
		currentHour := now.Hour()
		currentMinute := now.Minute()
		currentTime := currentHour*60 + currentMinute

		for _, tod := range timeMatch.TimeOfDay {
			startParts := strings.Split(tod.Start, ":")
			endParts := strings.Split(tod.End, ":")

			if len(startParts) != 2 || len(endParts) != 2 {
				klog.Warningf("Invalid time format: %s-%s", tod.Start, tod.End)
				continue
			}

			startHour := e.parseTimeComponent(startParts[0])
			startMinute := e.parseTimeComponent(startParts[1])
			startTime := startHour*60 + startMinute

			endHour := e.parseTimeComponent(endParts[0])
			endMinute := e.parseTimeComponent(endParts[1])
			endTime := endHour*60 + endMinute

			if currentTime >= startTime && currentTime <= endTime {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// ipInNetwork checks if an IP address is in a network
func (e *engine) ipInNetwork(ipStr, networkStr string) bool {
	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Parse network
	_, network, err := net.ParseCIDR(networkStr)
	if err != nil {
		// Try as a single IP
		networkIP := net.ParseIP(networkStr)
		if networkIP == nil {
			return false
		}
		return ip.Equal(networkIP)
	}

	// Check if IP is in network
	return network.Contains(ip)
}

// parseTimeComponent parses a time component (hour or minute)
func (e *engine) parseTimeComponent(component string) int {
	var value int
	_, err := fmt.Sscanf(component, "%d", &value)
	if err != nil {
		return 0
	}
	return value
}
