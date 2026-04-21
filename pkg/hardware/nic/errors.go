// Package nic provides functionality for managing network interfaces.
package nic

import "errors"

// Sentinel errors surfaced when the underlying driver / kernel does not expose
// the counter or feature the caller asked for. They let callers distinguish
// "driver does not support this" from a transient netlink / ethtool failure.
//
// These are defined in a platform-neutral file so both the Linux real path and
// the non-Linux stub can return identical sentinel errors and tests can use
// errors.Is on every platform.
var (
	// ErrNICStatisticsNotSupported is returned when the driver does not expose
	// any statistics for the requested interface (neither netlink link stats
	// nor ethtool -S counters).
	ErrNICStatisticsNotSupported = errors.New("NIC statistics not exposed by driver")

	// ErrNICFeatureNotSupported is returned when the driver does not expose any
	// offload feature flags for the requested interface.
	ErrNICFeatureNotSupported = errors.New("NIC feature not supported by driver")

	// ErrNICNotFound is returned when the requested interface is not present in
	// the manager cache and cannot be discovered via netlink.
	ErrNICNotFound = errors.New("NIC not found")

	// ErrNICUnsupportedPlatform is returned by the non-Linux stub for every
	// method that requires ethtool / netlink.
	ErrNICUnsupportedPlatform = errors.New("NIC management is only supported on linux")
)
