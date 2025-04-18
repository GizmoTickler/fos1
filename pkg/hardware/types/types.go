// Package types defines the types used by the hardware package
package types

import (
	"context"
)

// CaptureManager defines the interface for packet capture management
type CaptureManager interface {
	// Initialize initializes the capture manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the capture manager
	Shutdown(ctx context.Context) error

	// StartCapture starts a new packet capture
	StartCapture(config CaptureConfig) (string, error)

	// StopCapture stops a packet capture
	StopCapture(captureID string) error

	// GetCaptureStatus gets the status of a packet capture
	GetCaptureStatus(captureID string) (*CaptureStatus, error)

	// ListCaptures lists all packet captures
	ListCaptures() ([]string, error)

	// GetCapturePath returns the path to a capture file
	GetCapturePath(captureID string) (string, error)
}

// CaptureConfig defines the configuration for a packet capture
type CaptureConfig struct {
	// Interface is the interface to capture on
	Interface string

	// Filter is the capture filter expression
	Filter string

	// Filename is the output filename
	Filename string

	// MaxDuration is the maximum duration to capture
	MaxDuration string

	// MaxSize is the maximum file size
	MaxSize string
}

// CaptureStatus defines the status of a packet capture
type CaptureStatus struct {
	// ID is the unique identifier for the capture
	ID string

	// Interface is the interface being captured
	Interface string

	// Filter is the capture filter expression
	Filter string

	// StartTime is the time the capture started
	StartTime string

	// Duration is the duration of the capture
	Duration string

	// Size is the size of the capture file in bytes
	Size int64

	// PacketCount is the number of packets captured
	PacketCount int64

	// Status is the current status of the capture
	Status string

	// Error is the error message if the capture failed
	Error string
}
