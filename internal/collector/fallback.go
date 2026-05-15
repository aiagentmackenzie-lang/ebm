package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type fallbackCollector struct {
	mu       sync.Mutex
	seenPIDs map[int32]int64 // pid -> last seen timestamp (unix nano)
}

func newFallbackCollector() *fallbackCollector {
	return &fallbackCollector{
		seenPIDs: make(map[int32]int64),
	}
}

func (f *fallbackCollector) Start(ctx context.Context, out chan<- map[string]interface{}) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Track network connections by 4-tuple to deduplicate
	type connKey struct {
		localIP   string
		localPort uint32
		remoteIP  string
		remotePort uint32
		proto     uint32
	}
	var prevConns map[connKey]bool

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			now := time.Now().UnixNano()

			// Process events — only emit new or recently-seen PIDs
			procs, err := process.Processes()
			if err != nil {
				slog.Error("fallback: failed to list processes", "error", err)
				continue
			}

			f.mu.Lock()
			activePIDs := make(map[int32]bool, len(procs))
			for _, p := range procs {
				pid := p.Pid
				activePIDs[pid] = true

				// Only emit if we haven't seen this PID before
				if _, seen := f.seenPIDs[pid]; !seen {
					name, _ := p.Name()
					cmdline, _ := p.Cmdline()
					exe, _ := p.Exe()
					ppid, _ := p.Ppid()

					raw := map[string]interface{}{
						"event.type":           "process_start",
						"event.platform":       "fallback",
						"event.provider":       "gopsutil",
						"process.pid":          int(pid),
						"process.name":         name,
						"process.command_line": cmdline,
						"process.executable":   exe,
						"process.parent.pid":   int(ppid),
						"severity":             "info",
					}

					select {
					case out <- raw:
					case <-ctx.Done():
						f.mu.Unlock()
						return ctx.Err()
					}
				}
				f.seenPIDs[pid] = now
			}

			// Prune PIDs not seen in the last 120 seconds (processes that exited)
			for pid, ts := range f.seenPIDs {
				if !activePIDs[pid] && now-ts > 120_000_000_000 { // 120s in nanos
					delete(f.seenPIDs, pid)
				}
			}
			f.mu.Unlock()

			// Network connections — deduplicate by 4-tuple, only emit new connections
			conns, err := net.Connections("all")
			if err != nil {
				slog.Error("fallback: failed to list connections", "error", err)
				continue
			}

			currentConns := make(map[connKey]bool, len(conns))
			for _, c := range conns {
				key := connKey{
					localIP:    c.Laddr.IP,
					localPort:  c.Laddr.Port,
					remoteIP:   c.Raddr.IP,
					remotePort: c.Raddr.Port,
					proto:      c.Type,
				}
				currentConns[key] = true

				// Only emit if this connection wasn't in the previous snapshot
				if prevConns == nil || !prevConns[key] {
					raw := map[string]interface{}{
						"event.type":          "network_connect",
						"event.platform":      "fallback",
						"event.provider":      "gopsutil",
						"source.ip":           c.Laddr.IP,
						"source.port":         int(c.Laddr.Port),
						"destination.ip":     c.Raddr.IP,
						"destination.port":   int(c.Raddr.Port),
						"network.transport":  connTypeStr(c.Type),
						"severity":            "info",
					}
					select {
					case out <- raw:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
			prevConns = currentConns
		}
	}
}

func (f *fallbackCollector) Stop() error {
	return nil
}

// connTypeStr converts a gopsutil connection type uint32 to a string.
func connTypeStr(t uint32) string {
	switch t {
	case 1:
		return "icmp"
	case 2:
		return "tcp"
	case 3:
		return "udp"
	default:
		return fmt.Sprintf("%d", t)
	}
}