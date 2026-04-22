// Allowlist handling for expressions that are not expected to resolve in
// the Kind proof cluster. Matching is a byte-for-byte comparison of the
// trimmed expression text; comments and empty lines are ignored.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Allowlist holds the set of PromQL expressions that should be skipped
// when running the validator. Callers should use Contains() to test
// membership; the type tracks the original source lines for diagnostic
// reporting.
type Allowlist struct {
	expressions map[string]struct{}
	source      string
}

// LoadAllowlist reads an allowlist file. Blank lines and lines starting
// with `#` are ignored. Returns an empty Allowlist when the file does
// not exist — that case is not an error because validator runs in
// projects that have not yet adopted an allowlist should still succeed.
func LoadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{
		expressions: map[string]struct{}{},
		source:      path,
	}
	if path == "" {
		return a, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return a, nil
		}
		return nil, fmt.Errorf("open allowlist %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Expressions can be long; expand the buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		a.expressions[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist %s: %w", path, err)
	}
	return a, nil
}

// Contains reports whether the given PromQL expression is allowlisted.
// The comparison is on the trimmed expression text. Case-sensitive.
func (a *Allowlist) Contains(expr string) bool {
	if a == nil {
		return false
	}
	_, ok := a.expressions[strings.TrimSpace(expr)]
	return ok
}

// Size returns the number of allowlisted entries.
func (a *Allowlist) Size() int {
	if a == nil {
		return 0
	}
	return len(a.expressions)
}

// Source returns the file path the allowlist was loaded from (may be
// empty if none was configured).
func (a *Allowlist) Source() string {
	if a == nil {
		return ""
	}
	return a.source
}
