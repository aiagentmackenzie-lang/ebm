package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type fallbackCollector struct{}

func newFallbackCollector() *fallbackCollector {
	return &fallbackCollector{}
}

func (f *fallbackCollector) Start(ctx context.Context, out chan<- map[string]interface{}) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	seen := make(map[int32]bool)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			procs, err := process.Processes()
			if err != nil {
				slog.Error("fallback: failed to list processes", "error", err)
				continue
			}
			for _, p := range procs {
				pid := p.Pid
				name, _ := p.Name()
				cmdline, _ := p.Cmdline()
				exe, _ := p.Exe()
				ppid, _ := p.Ppid()

				raw := map[string]interface{}{
					"event.type":          "process_start",
					"event.platform":      "fallback",
					"event.provider":      "gopsutil",
					"process.pid":         int(pid),
					"process.name":        name,
					"process.command_line": cmdline,
					"process.executable":   exe,
					"process.parent.pid":  int(ppid),
					"severity":            "info",
				}

				if !seen[pid] {
					seen[pid] = true
					select {
					case out <- raw:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}

			conns, err := net.Connections("all")
			if err != nil {
				slog.Error("fallback: failed to list connections", "error", err)
				continue
			}
			for _, c := range conns {
				raw := map[string]interface{}{
					"event.type":          "network_connect",
					"event.platform":      "fallback",
					"event.provider":      "gopsutil",
					"source.ip":           c.Laddr.IP,
					"source.port":         int(c.Laddr.Port),
					"destination.ip":      c.Raddr.IP,
					"destination.port":  int(c.Raddr.Port),
					"network.transport":   c.Type,
					"severity":            "info",
				}
				select {
				case out <- raw:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

func (f *fallbackCollector) Stop() error {
	return nil
}
