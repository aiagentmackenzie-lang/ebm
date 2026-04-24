package transport

import (
	"time"
	"math/rand"
)

// Backoff computes the next retry delay using exponential backoff with jitter.
func Backoff(attempt int) time.Duration {
	base := time.Duration(1 << attempt) * time.Second
	if base > 300*time.Second {
		base = 300 * time.Second
	}
	jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
	return base + jitter
}
