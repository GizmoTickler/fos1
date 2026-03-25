package coredns

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WriteZoneFile writes a zone file in RFC 1035 format.
func WriteZoneFile(zone *Zone, path string) error {
	if zone == nil {
		return fmt.Errorf("zone is nil")
	}
	if path == "" {
		return fmt.Errorf("path is empty")
	}

	// Ensure the parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create zone file %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	domain := ensureTrailingDot(zone.Domain)

	// Write header comment
	fmt.Fprintf(w, "; Zone file for %s\n", zone.Domain)
	fmt.Fprintf(w, "; Generated at %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "; ConfigGen: %d\n", zone.ConfigGen)
	fmt.Fprintln(w)

	// Write $TTL directive
	defaultTTL := int32(3600)
	if zone.SOA != nil && zone.SOA.Minimum > 0 {
		defaultTTL = int32(zone.SOA.Minimum)
	}
	fmt.Fprintf(w, "$TTL\t%d\n", defaultTTL)
	fmt.Fprintln(w)

	// Write SOA record
	if zone.SOA != nil {
		soa := zone.SOA
		fmt.Fprintf(w, "%s\tIN\tSOA\t%s %s (\n",
			domain,
			ensureTrailingDot(soa.MName),
			ensureTrailingDot(soa.RName),
		)
		fmt.Fprintf(w, "\t\t\t\t%d\t; Serial\n", soa.Serial)
		fmt.Fprintf(w, "\t\t\t\t%d\t; Refresh\n", soa.Refresh)
		fmt.Fprintf(w, "\t\t\t\t%d\t; Retry\n", soa.Retry)
		fmt.Fprintf(w, "\t\t\t\t%d\t; Expire\n", soa.Expire)
		fmt.Fprintf(w, "\t\t\t\t%d\t; Minimum TTL\n", soa.Minimum)
		fmt.Fprintln(w, "\t\t\t\t)")
		fmt.Fprintln(w)
	}

	// Write NS records (derived from SOA MName if present)
	if zone.SOA != nil && zone.SOA.MName != "" {
		fmt.Fprintf(w, "%s\tIN\tNS\t%s\n", domain, ensureTrailingDot(zone.SOA.MName))
		fmt.Fprintln(w)
	}

	// Group records by type for organized output
	grouped := groupRecordsByType(zone.Records)
	typeOrder := []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR"}

	for _, rtype := range typeOrder {
		records, ok := grouped[rtype]
		if !ok || len(records) == 0 {
			continue
		}
		fmt.Fprintf(w, "; %s records\n", rtype)
		for _, rec := range records {
			writeRecord(w, rec, domain)
		}
		fmt.Fprintln(w)
	}

	// Write any remaining record types not in the ordered list
	for rtype, records := range grouped {
		if containsString(typeOrder, rtype) {
			continue
		}
		fmt.Fprintf(w, "; %s records\n", rtype)
		for _, rec := range records {
			writeRecord(w, rec, domain)
		}
		fmt.Fprintln(w)
	}

	return w.Flush()
}

// ParseZoneFile reads a zone file and returns a Zone.
func ParseZoneFile(path string, zoneName string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open zone file %s: %w", path, err)
	}
	defer f.Close()

	zone := &Zone{
		Name:    zoneName,
		Domain:  zoneName,
		Records: make([]*DNSRecord, 0),
	}

	scanner := bufio.NewScanner(f)
	var inSOA bool
	var soaLines []string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			// Check for ConfigGen comment
			if strings.HasPrefix(trimmed, "; ConfigGen:") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "; ConfigGen:"))
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					zone.ConfigGen = n
				}
			}
			continue
		}

		// Handle $TTL directive
		if strings.HasPrefix(trimmed, "$TTL") {
			continue
		}

		// Handle $ORIGIN directive
		if strings.HasPrefix(trimmed, "$ORIGIN") {
			continue
		}

		// Detect SOA record start
		if !inSOA && strings.Contains(trimmed, "\tSOA\t") || strings.Contains(trimmed, " SOA ") {
			inSOA = true
			soaLines = []string{trimmed}
			if strings.Contains(trimmed, ")") {
				inSOA = false
				zone.SOA = parseSOALines(soaLines)
			}
			continue
		}

		// Continue collecting SOA lines
		if inSOA {
			soaLines = append(soaLines, trimmed)
			if strings.Contains(trimmed, ")") {
				inSOA = false
				zone.SOA = parseSOALines(soaLines)
			}
			continue
		}

		// Parse NS record
		if strings.Contains(trimmed, "\tNS\t") || strings.Contains(trimmed, " NS ") {
			// NS records are part of zone metadata, skip adding to records list
			continue
		}

		// Parse standard records
		rec := parseRecordLine(trimmed, zoneName)
		if rec != nil {
			zone.Records = append(zone.Records, rec)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading zone file: %w", err)
	}

	zone.Updated = time.Now()
	return zone, nil
}

// GenerateCorefile generates CoreDNS Corefile configuration for the given zones.
func GenerateCorefile(zones []*Zone, listenAddr string, configDir string) (string, error) {
	if len(zones) == 0 {
		return "", fmt.Errorf("no zones provided")
	}
	if listenAddr == "" {
		listenAddr = ":53"
	}
	if configDir == "" {
		return "", fmt.Errorf("configDir is required")
	}

	var b strings.Builder

	// Write a header comment
	fmt.Fprintln(&b, "# CoreDNS Corefile - auto-generated")
	fmt.Fprintf(&b, "# Generated at %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(&b)

	// Generate a server block for each zone
	for _, zone := range zones {
		domain := zone.Domain
		if domain == "" {
			domain = zone.Name
		}
		zoneFilePath := filepath.Join(configDir, zoneFileName(domain))

		fmt.Fprintf(&b, "%s:%s {\n", domain, strings.TrimPrefix(listenAddr, ":"))
		fmt.Fprintf(&b, "    file %s\n", zoneFilePath)
		fmt.Fprintln(&b, "    reload 5s")
		fmt.Fprintln(&b, "    errors")
		fmt.Fprintln(&b, "    log")
		fmt.Fprintln(&b, "}")
		fmt.Fprintln(&b)
	}

	// Add a catch-all forward block
	fmt.Fprintf(&b, ".:%s {\n", strings.TrimPrefix(listenAddr, ":"))
	fmt.Fprintln(&b, "    forward . /etc/resolv.conf")
	fmt.Fprintln(&b, "    cache 30")
	fmt.Fprintln(&b, "    errors")
	fmt.Fprintln(&b, "    log")
	fmt.Fprintln(&b, "}")
	fmt.Fprintln(&b)

	return b.String(), nil
}

// IncrementSerial auto-increments the SOA serial number using YYYYMMDDnn format.
func IncrementSerial(zone *Zone) uint32 {
	if zone == nil || zone.SOA == nil {
		return 0
	}

	now := time.Now()
	datePrefix := uint32(now.Year()%10000)*10000 +
		uint32(now.Month())*100 +
		uint32(now.Day())
	dateBase := datePrefix * 100

	current := zone.SOA.Serial

	if current >= dateBase && current < dateBase+99 {
		// Same day, increment the sequence number
		zone.SOA.Serial = current + 1
	} else if current >= dateBase+99 {
		// Overflow for today, just increment
		zone.SOA.Serial = current + 1
	} else {
		// New day or first serial in this format
		zone.SOA.Serial = dateBase + 1
	}

	return zone.SOA.Serial
}

// --- Helper functions ---

// ensureTrailingDot ensures a domain name ends with a dot.
func ensureTrailingDot(s string) string {
	if s == "" {
		return "."
	}
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// stripTrailingDot removes a trailing dot from a domain name.
func stripTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

// zoneFileName returns the zone file name for a domain.
func zoneFileName(domain string) string {
	return "db." + stripTrailingDot(domain)
}

// groupRecordsByType groups DNS records by their type.
func groupRecordsByType(records []*DNSRecord) map[string][]*DNSRecord {
	grouped := make(map[string][]*DNSRecord)
	for _, rec := range records {
		grouped[rec.Type] = append(grouped[rec.Type], rec)
	}
	// Sort each group by name
	for _, recs := range grouped {
		sort.Slice(recs, func(i, j int) bool {
			return recs[i].Name < recs[j].Name
		})
	}
	return grouped
}

// containsString checks if a slice contains a string.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// writeRecord writes a single DNS record line to the writer.
func writeRecord(w *bufio.Writer, rec *DNSRecord, zoneDomain string) {
	name := rec.Name
	if name == "" || name == "@" || name == stripTrailingDot(zoneDomain) {
		name = "@"
	}

	value := rec.Value
	switch rec.Type {
	case "CNAME", "PTR":
		value = ensureTrailingDot(value)
	case "MX":
		// MX records: value should be "priority target"
		// Ensure target has trailing dot
		parts := strings.Fields(value)
		if len(parts) == 2 {
			value = parts[0] + "\t" + ensureTrailingDot(parts[1])
		} else if len(parts) == 1 {
			value = "10\t" + ensureTrailingDot(parts[0])
		}
	case "SRV":
		// SRV records: value should be "priority weight port target"
		parts := strings.Fields(value)
		if len(parts) == 4 {
			value = parts[0] + "\t" + parts[1] + "\t" + parts[2] + "\t" + ensureTrailingDot(parts[3])
		}
	case "TXT":
		// Ensure TXT records are quoted
		if !strings.HasPrefix(value, "\"") {
			value = "\"" + value + "\""
		}
	}

	if rec.TTL > 0 {
		fmt.Fprintf(w, "%s\t%d\tIN\t%s\t%s\n", name, rec.TTL, rec.Type, value)
	} else {
		fmt.Fprintf(w, "%s\tIN\t%s\t%s\n", name, rec.Type, value)
	}
}

// parseSOALines parses collected SOA lines into an SOARecord.
func parseSOALines(lines []string) *SOARecord {
	if len(lines) == 0 {
		return nil
	}

	soa := &SOARecord{}

	// Join all lines and parse
	joined := strings.Join(lines, " ")
	// Remove parentheses and comments
	joined = strings.ReplaceAll(joined, "(", " ")
	joined = strings.ReplaceAll(joined, ")", " ")

	// Remove inline comments
	var cleaned []string
	for _, part := range strings.Split(joined, ";") {
		if len(cleaned) == 0 {
			cleaned = append(cleaned, part)
		}
		break
	}
	// Actually, we need to extract numbers from all lines
	// Re-parse: extract the SOA fields
	// Format: <name> IN SOA <mname> <rname> <serial> <refresh> <retry> <expire> <minimum>

	// Get mname and rname from first line
	firstLine := lines[0]
	// Remove comments from first line
	if idx := strings.Index(firstLine, ";"); idx >= 0 {
		firstLine = firstLine[:idx]
	}
	fields := strings.Fields(firstLine)

	// Find SOA keyword position
	soaIdx := -1
	for i, f := range fields {
		if strings.EqualFold(f, "SOA") {
			soaIdx = i
			break
		}
	}

	if soaIdx >= 0 && soaIdx+2 < len(fields) {
		soa.MName = stripTrailingDot(fields[soaIdx+1])
		soa.RName = stripTrailingDot(fields[soaIdx+2])
	}

	// Extract all numbers from remaining lines
	var numbers []uint32
	for _, line := range lines {
		// Remove comments
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.ReplaceAll(line, "(", " ")
		line = strings.ReplaceAll(line, ")", " ")
		for _, field := range strings.Fields(line) {
			if n, err := strconv.ParseUint(field, 10, 32); err == nil {
				numbers = append(numbers, uint32(n))
			}
		}
	}

	// Assign numbers: serial, refresh, retry, expire, minimum
	if len(numbers) >= 1 {
		soa.Serial = numbers[0]
	}
	if len(numbers) >= 2 {
		soa.Refresh = numbers[1]
	}
	if len(numbers) >= 3 {
		soa.Retry = numbers[2]
	}
	if len(numbers) >= 4 {
		soa.Expire = numbers[3]
	}
	if len(numbers) >= 5 {
		soa.Minimum = numbers[4]
	}

	return soa
}

// parseRecordLine parses a single resource record line.
func parseRecordLine(line string, zoneDomain string) *DNSRecord {
	// Remove trailing comments
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	rec := &DNSRecord{}

	// Parse: name [ttl] [class] type value...
	idx := 0

	// First field is the name
	rec.Name = fields[idx]
	if rec.Name == "@" {
		rec.Name = "@"
	}
	// Strip trailing dot from record name if it matches zone domain
	rec.Name = stripTrailingDot(rec.Name)
	idx++

	// Check for TTL (numeric field)
	if idx < len(fields) {
		if ttl, err := strconv.ParseInt(fields[idx], 10, 32); err == nil {
			rec.TTL = int32(ttl)
			idx++
		}
	}

	// Check for class (IN, CH, HS)
	if idx < len(fields) && isClass(fields[idx]) {
		idx++
	}

	// Next field is the record type
	if idx >= len(fields) {
		return nil
	}
	rec.Type = strings.ToUpper(fields[idx])
	idx++

	// Remaining fields are the value
	if idx >= len(fields) {
		return nil
	}

	valueParts := fields[idx:]
	value := strings.Join(valueParts, " ")

	// Clean up values based on type
	switch rec.Type {
	case "CNAME", "PTR":
		value = stripTrailingDot(value)
	case "MX":
		// Keep as "priority target" but strip trailing dot from target
		parts := strings.Fields(value)
		if len(parts) >= 2 {
			value = parts[0] + " " + stripTrailingDot(parts[1])
		}
	case "SRV":
		parts := strings.Fields(value)
		if len(parts) >= 4 {
			value = parts[0] + " " + parts[1] + " " + parts[2] + " " + stripTrailingDot(parts[3])
		}
	case "TXT":
		// Remove surrounding quotes for storage
		value = strings.Trim(value, "\"")
	case "A", "AAAA":
		// No modification needed
	}

	rec.Value = value

	// Validate record type
	validTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true,
		"TXT": true, "SRV": true, "PTR": true, "NS": true,
		"CAA": true, "TLSA": true, "DNSKEY": true, "DS": true,
	}
	if !validTypes[rec.Type] {
		return nil
	}

	return rec
}

// isClass returns true if the string is a DNS class.
func isClass(s string) bool {
	upper := strings.ToUpper(s)
	return upper == "IN" || upper == "CH" || upper == "HS" || upper == "ANY"
}
