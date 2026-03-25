package coredns

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ReloadZones triggers CoreDNS to reload zone files.
// CoreDNS uses the `reload` plugin which watches for file changes.
// This function touches the zone files to update their modification time,
// causing CoreDNS to detect changes and reload.
func ReloadZones(zoneDir string) error {
	if zoneDir == "" {
		return fmt.Errorf("zone directory is required")
	}

	entries, err := os.ReadDir(zoneDir)
	if err != nil {
		return fmt.Errorf("failed to read zone directory %s: %w", zoneDir, err)
	}

	now := time.Now()
	touchedCount := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Only touch zone files (db.* files) and the Corefile
		if isZoneFile(name) || name == "Corefile" {
			path := filepath.Join(zoneDir, name)
			if err := os.Chtimes(path, now, now); err != nil {
				return fmt.Errorf("failed to touch file %s: %w", path, err)
			}
			touchedCount++
		}
	}

	if touchedCount == 0 {
		return fmt.Errorf("no zone files found in %s", zoneDir)
	}

	return nil
}

// WriteAndReload writes all zones to disk and triggers a CoreDNS reload.
func WriteAndReload(zones []*Zone, zoneDir string) error {
	if zoneDir == "" {
		return fmt.Errorf("zone directory is required")
	}
	if len(zones) == 0 {
		return fmt.Errorf("no zones to write")
	}

	// Ensure the zone directory exists
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		return fmt.Errorf("failed to create zone directory %s: %w", zoneDir, err)
	}

	// Write each zone file
	for _, zone := range zones {
		if zone == nil {
			continue
		}
		domain := zone.Domain
		if domain == "" {
			domain = zone.Name
		}
		path := filepath.Join(zoneDir, zoneFileName(domain))

		// Increment serial before writing
		IncrementSerial(zone)

		if err := WriteZoneFile(zone, path); err != nil {
			return fmt.Errorf("failed to write zone file for %s: %w", domain, err)
		}
	}

	// Generate and write Corefile
	corefilePath := filepath.Join(zoneDir, "Corefile")
	corefile, err := GenerateCorefile(zones, ":53", zoneDir)
	if err != nil {
		return fmt.Errorf("failed to generate Corefile: %w", err)
	}
	if err := os.WriteFile(corefilePath, []byte(corefile), 0644); err != nil {
		return fmt.Errorf("failed to write Corefile: %w", err)
	}

	// Trigger reload by touching the files
	if err := ReloadZones(zoneDir); err != nil {
		return fmt.Errorf("failed to trigger CoreDNS reload: %w", err)
	}

	return nil
}

// isZoneFile returns true if the filename looks like a zone file.
func isZoneFile(name string) bool {
	return len(name) > 3 && name[:3] == "db."
}
