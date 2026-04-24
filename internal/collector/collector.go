// Package collector abstracts platform-specific telemetry sources.
package collector

import (
	"context"
	"fmt"
	"runtime"
)

// Collector is the interface implemented by all platform collectors.
type Collector interface {
	Start(ctx context.Context, out chan<- map[string]interface{}) error
	Stop() error
}

// New returns the platform-appropriate collector implementation.
func New() (Collector, error) {
	switch runtime.GOOS {
	case "windows":
		return newFallbackCollector(), nil
	case "linux":
		return newFallbackCollector(), nil
	case "darwin":
		return newFallbackCollector(), nil
	default:
		return newFallbackCollector(), nil
	}
}

// windowsCollector collects Sysmon/ETW telemetry on Windows.
type windowsCollector struct{}

func newWindowsCollector() *windowsCollector {
	return &windowsCollector{}
}

func (w *windowsCollector) Start(ctx context.Context, out chan<- map[string]interface{}) error {
	return fmt.Errorf("windows collector not yet implemented")
}

func (w *windowsCollector) Stop() error {
	return nil
}

// linuxCollector collects telemetry via eBPF and fallback /proc on Linux.
type linuxCollector struct{}

func newLinuxCollector() *linuxCollector {
	return &linuxCollector{}
}

func (l *linuxCollector) Start(ctx context.Context, out chan<- map[string]interface{}) error {
	return fmt.Errorf("linux collector not yet implemented")
}

func (l *linuxCollector) Stop() error {
	return nil
}

// darwinCollector collects telemetry via Endpoint Security Framework on macOS.
type darwinCollector struct{}

func newDarwinCollector() *darwinCollector {
	return &darwinCollector{}
}

func (d *darwinCollector) Start(ctx context.Context, out chan<- map[string]interface{}) error {
	return fmt.Errorf("darwin collector not yet implemented")
}

func (d *darwinCollector) Stop() error {
	return nil
}
