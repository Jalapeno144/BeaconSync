package scheduler

import (
	cryptorand "crypto/rand"
	"math/big"
	"time"
)

type HeartbeatConfig struct {
	BaseInterval time.Duration // Base time
	JitterAbs    time.Duration // Shake of time
	MinInterval  time.Duration // Upper bound of the interval
	MaxInterval  time.Duration // Lower bound of the interval
}

// DefaultHeartbeatConfig, return a default HeartbeatConfig structure
// time range from 75s to 105s
func DefaultHeartbeatConfig() HeartbeatConfig {
	return HeartbeatConfig{
		BaseInterval: 90 * time.Second,
		JitterAbs:    15 * time.Second,
		MinInterval:  60 * time.Second,
		MaxInterval:  120 * time.Second,
	}
}

// Set JitterAbs manually
func (c *HeartbeatConfig) SetJitterAbs(d time.Duration, jitterPercent float64) {
	c.BaseInterval = d
	c.JitterAbs = time.Duration(float64(d) * jitterPercent)
	c.MinInterval = d - c.JitterAbs
	c.MaxInterval = d + c.JitterAbs + 1*time.Second
}

// Set BaseInterval manually
func (c *HeartbeatConfig) SetBaseInterval(d time.Duration) {
	c.BaseInterval = d
	c.JitterAbs = time.Duration(float64(d) * 0.2) // default JitterAbs is 20 percent of time
	c.MinInterval = d - c.JitterAbs
	c.MaxInterval = d + c.JitterAbs + 1*time.Second
}

func (c *HeartbeatConfig) clamp(d time.Duration) time.Duration {
	if d < c.MinInterval {
		return c.MinInterval
	}
	if d > c.MaxInterval {
		return c.MaxInterval
	}
	return d
}

// NextInterval returns the next heartbeat interval with jitter applied.
func (c *HeartbeatConfig) NextInterval() time.Duration {
	// No need to set Jitter
	if c.JitterAbs <= 0 {
		return c.BaseInterval
	}

	// Uniform random in [BaseInterval - JitterAbs, BaseInterval + JitterAbs]
	next := c.BaseInterval - c.JitterAbs + cryptoRandDuration(c.JitterAbs*2)

	return c.clamp(next)
}

// cryptoRandDuration returns a uniformly random time.Duration in [0, max) using
// crypto/rand. Panics if the CSPRNG is unavailable — on modern platforms
// crypto/rand.Reader never fails.
func cryptoRandDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	bi, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic("crypto/rand: CSPRNG is unavailable — " + err.Error())
	}
	return time.Duration(bi.Int64())
}
