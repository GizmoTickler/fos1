package chrony

import (
	"fmt"
	"strings"

	"github.com/fos/pkg/ntp"
)

// ConfigGenerator generates Chrony configuration from NTP service spec
type ConfigGenerator struct {
	// Dependencies and configuration
}

// NewConfigGenerator creates a new Chrony configuration generator
func NewConfigGenerator() *ConfigGenerator {
	return &ConfigGenerator{}
}

// Generate creates a Chrony configuration file from the NTP service spec
func (g *ConfigGenerator) Generate(service *ntp.NTPService) (string, error) {
	var config strings.Builder

	// Add server and pool directives for time sources
	if err := g.addSources(&config, &service.Sources); err != nil {
		return "", fmt.Errorf("failed to add sources: %w", err)
	}

	// Add server configuration
	if err := g.addServerConfig(&config, &service.Server); err != nil {
		return "", fmt.Errorf("failed to add server configuration: %w", err)
	}

	// Add security configuration
	if err := g.addSecurityConfig(&config, &service.Security); err != nil {
		return "", fmt.Errorf("failed to add security configuration: %w", err)
	}

	// Add logging configuration
	g.addLoggingConfig(&config)

	return config.String(), nil
}

// addSources adds time source configuration
func (g *ConfigGenerator) addSources(config *strings.Builder, sources *ntp.Sources) error {
	// Add pool sources
	for _, pool := range sources.Pools {
		preferFlag := ""
		if pool.Prefer {
			preferFlag = " prefer"
		}

		iburstFlag := ""
		if pool.IBurst {
			iburstFlag = " iburst"
		}

		fmt.Fprintf(config, "pool %s%s%s maxsources %d\n", 
			pool.Name, iburstFlag, preferFlag, pool.Servers)
	}

	// Add server sources
	for _, server := range sources.Servers {
		preferFlag := ""
		if server.Prefer {
			preferFlag = " prefer"
		}

		iburstFlag := ""
		if server.IBurst {
			iburstFlag = " iburst"
		}

		pollFlags := ""
		if server.MinPoll > 0 && server.MaxPoll > 0 {
			pollFlags = fmt.Sprintf(" minpoll %d maxpoll %d", server.MinPoll, server.MaxPoll)
		}

		fmt.Fprintf(config, "server %s%s%s%s\n", 
			server.Address, iburstFlag, preferFlag, pollFlags)
	}

	// Add hardware time sources if enabled
	if sources.Hardware.PPS.Enabled {
		preferFlag := ""
		if sources.Hardware.PPS.Prefer {
			preferFlag = " prefer"
		}
		fmt.Fprintf(config, "refclock PPS %s%s\n", sources.Hardware.PPS.Device, preferFlag)
	}

	if sources.Hardware.GPS.Enabled {
		preferFlag := ""
		if sources.Hardware.GPS.Prefer {
			preferFlag = " prefer"
		}
		refClockStr := ""
		if sources.Hardware.GPS.RefClock {
			refClockStr = " refid GPS"
		}
		fmt.Fprintf(config, "refclock SHM 0%s%s\n", refClockStr, preferFlag)
	}

	return nil
}

// addServerConfig adds server configuration
func (g *ConfigGenerator) addServerConfig(config *strings.Builder, server *ntp.ServerConfig) error {
	// Add driftfile
	fmt.Fprintf(config, "driftfile %s\n", server.DriftFile)

	// Add makestep configuration
	fmt.Fprintf(config, "makestep %f %d\n", server.MakeStep.Threshold, server.MakeStep.Limit)

	// Add local clock configuration if enabled
	if server.Local.Enabled {
		fmt.Fprintf(config, "local stratum %d\n", server.Local.Stratum)
	}

	return nil
}

// addSecurityConfig adds security configuration
func (g *ConfigGenerator) addSecurityConfig(config *strings.Builder, security *ntp.SecurityConfig) error {
	// Add Network Time Security (NTS) if enabled
	if security.NTS.Enabled {
		fmt.Fprintln(config, "ntsdumpdir /var/lib/chrony")
		fmt.Fprintln(config, "ntsservercert /etc/chrony/cert.pem")
		fmt.Fprintln(config, "ntsserverkey /etc/chrony/key.pem")
	}

	// Add authentication if enabled
	if security.Authentication.Enabled {
		fmt.Fprintln(config, "keyfile /etc/chrony/chrony.keys")
	}

	// Add rate limiting if enabled
	if security.RateLimit.Enabled {
		fmt.Fprintf(config, "ratelimit interval %d burst %d\n",
			security.RateLimit.Interval, security.RateLimit.Burst)
	}

	// Add access control rules
	for _, access := range security.Access {
		fmt.Fprintf(config, "%s %s\n", access.Permission, access.Network)
	}

	return nil
}

// addLoggingConfig adds logging configuration
func (g *ConfigGenerator) addLoggingConfig(config *strings.Builder) {
	fmt.Fprintln(config, "logdir /var/log/chrony")
	fmt.Fprintln(config, "log measurements statistics tracking")
}