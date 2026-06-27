package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// =============================================================================
// Backoff
// =============================================================================

// BackoffConfig controls exponential backoff behaviour when beacon
// transmissions fail.
type BackoffConfig struct {
	Initial    time.Duration // first retry delay
	Max        time.Duration // upper bound — the delay will never exceed this
	Multiplier float64       // multiplicative factor per consecutive failure
}

// DefaultBackoffConfig returns a BackoffConfig with sane defaults:
//
//	5s → 10s → 20s → 40s → ... → 10min (cap)
func DefaultBackoffConfig() BackoffConfig {
	return BackoffConfig{
		Initial:    5 * time.Second,
		Max:        10 * time.Minute,
		Multiplier: 2.0,
	}
}

// =============================================================================
// Task
// =============================================================================

// Task represents a unit of work dispatched by the server for local
// execution. The concrete command format is defined by the protocol layer;
// the scheduler treats it as opaque data.
type Task struct {
	ID      string
	Type    string
	Payload []byte
}

// =============================================================================
// State
// =============================================================================

// State describes the scheduler's operational mode.
type State int

const (
	StateStopped State = iota // not running
	StateRunning              // normal heartbeat cadence
	StateBackoff              // degraded — exponential backoff is active
	StateDormant              // deep sleep — prolonged outage, periodic wake-up
)

// String returns a human-readable label for the state.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateRunning:
		return "running"
	case StateBackoff:
		return "backoff"
	case StateDormant:
		return "dormant"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// =============================================================================
// Callback types
// =============================================================================

// BeaconFunc transmits a heartbeat beacon and returns the raw response
// body together with any error. The scheduler treats a non-nil error as
// a transmission failure and will engage backoff.
type BeaconFunc func() (response []byte, err error)

// TaskHandler is invoked for each task pulled from the internal queue.
type TaskHandler func(Task)

// =============================================================================
// Scheduler
// =============================================================================

// Scheduler is the central heartbeat engine for the BeaconSync client. It
// drives the beacon loop with jittered intervals, exponential backoff on
// failure, and graceful degradation into dormant mode under prolonged
// outages.
//
// The zero value is NOT usable; create one with New().
type Scheduler struct {
	hbCfg      HeartbeatConfig
	backoffCfg BackoffConfig

	sendFn       BeaconFunc
	taskHandlers []TaskHandler
	taskQueue    chan Task

	// Dormant threshold — after this many consecutive backoff failures
	// the scheduler enters dormant (deep-sleep) mode.
	maxBackoffRetries int
	dormantWakeup     time.Duration

	mu        sync.RWMutex
	state     State
	failCount int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// --- optional hooks ---

	// OnStateChange is called whenever the scheduler transitions
	// between states (e.g. running → backoff → dormant).
	OnStateChange func(oldState, newState State)

	// OnTick fires at the start of every sleep interval so callers
	// can display telemetry.
	OnTick func(interval time.Duration, state State)

	// Logger, when set, receives diagnostic messages. Defaults to
	// silent (no output).
	Logger func(format string, args ...interface{})
}

// =============================================================================
// Construction
// =============================================================================

// Option is a functional option for New().
type Option func(*Scheduler)

// New creates a Scheduler with sensible defaults. The caller must supply
// a BeaconFunc — everything else is optional.
func New(sendFn BeaconFunc, opts ...Option) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Scheduler{
		hbCfg:             DefaultHeartbeatConfig(),
		backoffCfg:        DefaultBackoffConfig(),
		sendFn:            sendFn,
		taskQueue:         make(chan Task, 64),
		maxBackoffRetries: 5,
		dormantWakeup:     30 * time.Minute,
		ctx:               ctx,
		cancel:            cancel,
		state:             StateStopped,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// --- functional options ---

// WithHeartbeatConfig overrides the default heartbeat parameters.
func WithHeartbeatConfig(hb HeartbeatConfig) Option {
	return func(s *Scheduler) { s.hbCfg = hb }
}

// WithBackoffConfig overrides the default exponential-backoff parameters.
func WithBackoffConfig(bo BackoffConfig) Option {
	return func(s *Scheduler) { s.backoffCfg = bo }
}

// WithTaskHandler registers a callback for tasks popped from the internal
// queue. May be passed multiple times; handlers are invoked in registration
// order.
func WithTaskHandler(h TaskHandler) Option {
	return func(s *Scheduler) { s.taskHandlers = append(s.taskHandlers, h) }
}

// WithMaxBackoffRetries sets how many consecutive backoff failures trigger
// the transition into dormant mode.
func WithMaxBackoffRetries(n int) Option {
	return func(s *Scheduler) { s.maxBackoffRetries = n }
}

// WithDormantWakeup sets the sleep duration between wake-up attempts when
// the scheduler is in dormant mode.
func WithDormantWakeup(d time.Duration) Option {
	return func(s *Scheduler) { s.dormantWakeup = d }
}

// =============================================================================
// Lifecycle
// =============================================================================

// Start begins the heartbeat loop in a background goroutine. It is a no-op
// when the scheduler is already running (including backoff / dormant).
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.state != StateStopped {
		s.mu.Unlock()
		return
	}
	s.setStateLocked(StateRunning)
	s.mu.Unlock()

	s.wg.Add(1)
	go s.loop()
}

// Stop gracefully shuts down the heartbeat loop and the internal task
// consumer. It blocks until both goroutines have exited.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if s.state == StateStopped {
		s.mu.Unlock()
		return
	}
	s.cancel()
	s.mu.Unlock()

	s.wg.Wait()
}

// Restart stops the scheduler (if running) and starts it again with a
// fresh context. Useful after a transport change.
func (s *Scheduler) Restart() {
	s.Stop()

	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.failCount = 0
	s.setStateLocked(StateRunning)
	s.mu.Unlock()

	s.wg.Add(1)
	go s.loop()
}

// =============================================================================
// Accessors
// =============================================================================

// State returns the current scheduler state. Safe for concurrent use.
func (s *Scheduler) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// HeartbeatConfig returns a copy of the active heartbeat configuration.
func (s *Scheduler) HeartbeatConfig() HeartbeatConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hbCfg
}

// SetHeartbeatConfig replaces the heartbeat configuration. Safe to call
// while the scheduler is running — new values take effect on the next
// tick.
func (s *Scheduler) SetHeartbeatConfig(hb HeartbeatConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hbCfg = hb
}

// TaskQueue returns a send-only channel that external callers (e.g. the
// protocol layer) can push tasks into. Tasks are consumed asynchronously
// by registered TaskHandlers.
func (s *Scheduler) TaskQueue() chan<- Task {
	return s.taskQueue
}

// FailCount returns the current consecutive failure count.
func (s *Scheduler) FailCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.failCount
}

// =============================================================================
// Internal: main loop
// =============================================================================

func (s *Scheduler) loop() {
	defer s.wg.Done()

	// Spin up the task consumer.
	s.wg.Add(1)
	go s.consumeTasks()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		interval := s.nextInterval()

		if s.OnTick != nil {
			s.OnTick(interval, s.State())
		}

		s.debug("[scheduler] next tick in %v (state=%s, fails=%d)", interval, s.State(), s.FailCount())

		select {
		case <-s.ctx.Done():
			return
		case <-time.After(interval):
		}

		resp, err := s.sendFn()
		if err != nil {
			s.recordFailure()
			continue
		}

		s.recordSuccess()

		// Feed response data to registered task handlers.
		if len(resp) > 0 && len(s.taskHandlers) > 0 {
			s.dispatchResponse(resp)
		}
	}
}

func (s *Scheduler) nextInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch s.state {
	case StateRunning:
		return s.hbCfg.NextInterval()
	case StateBackoff:
		d := float64(s.backoffCfg.Initial)
		for i := 1; i < s.failCount; i++ {
			d *= s.backoffCfg.Multiplier
		}
		if d > float64(s.backoffCfg.Max) {
			d = float64(s.backoffCfg.Max)
		}
		return time.Duration(d)
	case StateDormant:
		return s.dormantWakeup
	default:
		return 30 * time.Second
	}
}

// =============================================================================
// Internal: state transitions
// =============================================================================

func (s *Scheduler) recordFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failCount++

	switch s.state {
	case StateRunning:
		s.setStateLocked(StateBackoff)
		s.debug("[scheduler] beacon failed — entering backoff (fail=%d)", s.failCount)
	case StateBackoff:
		if s.failCount > s.maxBackoffRetries {
			s.setStateLocked(StateDormant)
			s.debug("[scheduler] backoff exhausted (%d retries) — entering dormant", s.failCount)
		}
	}
}

func (s *Scheduler) recordSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failCount = 0
	if s.state != StateRunning {
		s.debug("[scheduler] beacon recovered — returning to running")
		s.setStateLocked(StateRunning)
	}
}

// =============================================================================
// Internal: task dispatch
// =============================================================================

// dispatchResponse is a hook point for protocol-level task extraction.
// Currently it pushes the raw response as a single Task; callers can
// replace this logic by registering a TaskHandler that re-parses the
// queue entries, or by pushing pre-parsed tasks via TaskQueue() directly.
func (s *Scheduler) dispatchResponse(resp []byte) {
	task := Task{
		ID:      fmt.Sprintf("raw-%d", time.Now().UnixNano()),
		Type:    "raw_response",
		Payload: resp,
	}
	select {
	case s.taskQueue <- task:
	default:
		s.debug("[scheduler] task queue full — dropping raw response")
	}
}

// =============================================================================
// Internal: task consumer
// =============================================================================

func (s *Scheduler) consumeTasks() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case task := <-s.taskQueue:
			for _, h := range s.taskHandlers {
				h(task)
			}
		}
	}
}

// =============================================================================
// Internal: helpers
// =============================================================================

func (s *Scheduler) setStateLocked(newState State) {
	old := s.state
	if old == newState {
		return
	}
	s.state = newState
	if s.OnStateChange != nil {
		s.OnStateChange(old, newState)
	}
}

func (s *Scheduler) debug(format string, args ...interface{}) {
	if s.Logger != nil {
		s.Logger(format, args...)
	}
}
