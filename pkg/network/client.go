// Package network provides resilient HTTP client primitives with retry,
// timeout, and circuit-breaker support for upstream registry calls.
package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Client is an HTTP client with resilience features
type Client struct {
	client         *http.Client
	hopClient      *http.Client
	rateLimiter    *rate.Limiter
	circuitBreaker *CircuitBreaker
	retryConfig    RetryConfig
}

// Config holds client configuration
type Config struct {
	UserAgent       string
	CircuitBreaker  CircuitBreakerConfig
	Timeout         time.Duration
	MaxRetries      int
	RetryDelay      time.Duration
	RateLimit       float64
	RateBurst       int
	MaxConnsPerHost int
	// AllowPrivateRedirects lets a redirect to another host reach private, loopback or
	// link-local addresses. Off by default; it exists for tests and private mirrors.
	AllowPrivateRedirects bool
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	FixedDelays  []time.Duration
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled          bool
	FailureThreshold int           // Failures before opening
	SuccessThreshold int           // Successes before closing
	Timeout          time.Duration // How long to stay open
	HalfOpenMaxCalls int           // Max calls in half-open state
}

// CircuitBreakerState represents circuit breaker state
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	lastFailureTime time.Time
	config          CircuitBreakerConfig
	state           CircuitBreakerState
	failures        int
	successes       int
	halfOpenCalls   int
	mu              sync.RWMutex
}

// NewClient creates a new HTTP client with resilience features
func NewClient(config Config) *Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}

	if config.UserAgent == "" {
		config.UserAgent = "GoHoarder/1.0"
	}

	if config.MaxConnsPerHost == 0 {
		config.MaxConnsPerHost = 100
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: config.MaxConnsPerHost,
		MaxConnsPerHost:     config.MaxConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	httpClient := &http.Client{
		Timeout:       config.Timeout,
		Transport:     transport,
		CheckRedirect: noAutoRedirect,
	}

	hopTransport := transport.Clone()
	if !config.AllowPrivateRedirects {
		hopTransport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, Control: refusePrivateAddress}).DialContext
	}
	hopClient := &http.Client{
		Timeout:       config.Timeout,
		Transport:     hopTransport,
		CheckRedirect: noAutoRedirect,
	}

	var rateLimiter *rate.Limiter
	if config.RateLimit > 0 {
		if config.RateBurst == 0 {
			config.RateBurst = int(config.RateLimit)
		}
		rateLimiter = rate.NewLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	var cb *CircuitBreaker
	if config.CircuitBreaker.Enabled {
		if config.CircuitBreaker.FailureThreshold == 0 {
			config.CircuitBreaker.FailureThreshold = 5
		}
		if config.CircuitBreaker.SuccessThreshold == 0 {
			config.CircuitBreaker.SuccessThreshold = 2
		}
		if config.CircuitBreaker.Timeout == 0 {
			config.CircuitBreaker.Timeout = 60 * time.Second
		}
		if config.CircuitBreaker.HalfOpenMaxCalls == 0 {
			config.CircuitBreaker.HalfOpenMaxCalls = 3
		}

		cb = &CircuitBreaker{
			config: config.CircuitBreaker,
			state:  StateClosed,
		}
	}

	return &Client{
		client:         httpClient,
		hopClient:      hopClient,
		rateLimiter:    rateLimiter,
		circuitBreaker: cb,
		retryConfig: RetryConfig{
			MaxAttempts:  config.MaxRetries,
			InitialDelay: config.RetryDelay,
			MaxDelay:     30 * time.Second,
			Multiplier:   2.0,
			// Fixed delays: 1s, 5s, 10s for retry attempts 1, 2, 3
			FixedDelays: []time.Duration{1 * time.Second, 5 * time.Second, 10 * time.Second},
		},
	}
}

// Get performs a GET request with resilience features
func (c *Client) Get(ctx context.Context, rawURL string, headers map[string]string) (io.ReadCloser, int, error) {
	return c.GetWithRedirectCheck(ctx, rawURL, headers, nil)
}

// GetWithRedirectCheck is Get with a policy that every redirect target must pass.
// Redirects are always capped, limited to http(s), and refused when they reach a
// private address on another host; check adds an allowlist on top.
func (c *Client) GetWithRedirectCheck(ctx context.Context, rawURL string, headers map[string]string, check RedirectCheck) (io.ReadCloser, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeUpstreamError, "failed to create request")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.do(ctx, req, check)
	if err != nil {
		return nil, 0, err
	}

	return resp.Body, resp.StatusCode, nil
}

// do executes an HTTP request with retries and circuit breaker
func (c *Client) do(ctx context.Context, req *http.Request, check RedirectCheck) (*http.Response, error) {
	// Check circuit breaker
	if c.circuitBreaker != nil {
		if !c.circuitBreaker.AllowRequest() {
			metrics.UpdateCircuitBreakerState("upstream", int(StateOpen))
			return nil, errors.New(errors.ErrCodeCircuitOpen, "circuit breaker is open")
		}
	}

	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeRateLimited, "rate limit exceeded")
		}
	}

	// Execute with retries
	var lastErr error
	delay := c.retryConfig.InitialDelay

	for attempt := 0; attempt < c.retryConfig.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate delay: use fixed delays if configured, otherwise exponential backoff
			if len(c.retryConfig.FixedDelays) > 0 {
				// Use fixed delay schedule
				delayIndex := attempt - 1
				if delayIndex < len(c.retryConfig.FixedDelays) {
					delay = c.retryConfig.FixedDelays[delayIndex]
				} else {
					// Use last delay if we run out of configured delays
					delay = c.retryConfig.FixedDelays[len(c.retryConfig.FixedDelays)-1]
				}
			} else {
				// Exponential backoff
				delay = time.Duration(float64(delay) * c.retryConfig.Multiplier)
				if delay > c.retryConfig.MaxDelay {
					delay = c.retryConfig.MaxDelay
				}
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}

			log.Debug().
				Str("url", req.URL.String()).
				Int("attempt", attempt+1).
				Dur("delay", delay).
				Msg("Retrying request")
		}

		resp, err := c.send(req, check)
		if err != nil {
			lastErr = err
			continue
		}
		// Check if response is retryable
		if c.isRetryable(resp.StatusCode) {
			_ = resp.Body.Close() // #nosec G104 -- Cleanup, error not critical
			lastErr = fmt.Errorf("received retryable status code: %d", resp.StatusCode)
			continue
		}

		// Success
		if c.circuitBreaker != nil {
			c.circuitBreaker.RecordSuccess()
			metrics.UpdateCircuitBreakerState("upstream", int(StateClosed))
		}

		return resp, nil
	}

	// All retries exhausted
	if c.circuitBreaker != nil {
		c.circuitBreaker.RecordFailure()
	}

	if lastErr != nil {
		return nil, errors.Wrap(lastErr, errors.ErrCodeUpstreamFailure, "all retry attempts failed")
	}

	return nil, errors.New(errors.ErrCodeUpstreamFailure, "request failed without error")
}

// isRetryable checks if a status code should trigger a retry
func (c *Client) isRetryable(statusCode int) bool {
	// Retry on server errors and some client errors
	return statusCode >= 500 || statusCode == 408 || statusCode == 429
}

// AllowRequest checks if a request is allowed by the circuit breaker
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		// Check if timeout has elapsed
		if time.Since(cb.lastFailureTime) > cb.config.Timeout {
			cb.state = StateHalfOpen
			cb.halfOpenCalls = 0
			cb.successes = 0
			log.Info().Msg("Circuit breaker transitioning to half-open")
			metrics.UpdateCircuitBreakerState("upstream", int(StateHalfOpen))
			return true
		}
		return false

	case StateHalfOpen:
		// Allow limited requests in half-open state
		if cb.halfOpenCalls < cb.config.HalfOpenMaxCalls {
			cb.halfOpenCalls++
			return true
		}
		return false

	default:
		return false
	}
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		cb.failures = 0

	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.state = StateClosed
			cb.failures = 0
			cb.successes = 0
			cb.halfOpenCalls = 0
			log.Info().Msg("Circuit breaker closed")
			metrics.UpdateCircuitBreakerState("upstream", int(StateClosed))
		}
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.config.FailureThreshold {
			cb.state = StateOpen
			log.Warn().Int("failures", cb.failures).Msg("Circuit breaker opened")
			metrics.UpdateCircuitBreakerState("upstream", int(StateOpen))
		}

	case StateHalfOpen:
		// Single failure in half-open returns to open
		cb.state = StateOpen
		cb.halfOpenCalls = 0
		cb.successes = 0
		log.Warn().Msg("Circuit breaker re-opened from half-open")
		metrics.UpdateCircuitBreakerState("upstream", int(StateOpen))
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// MaxRedirects caps the hops one request may follow.
const MaxRedirects = 10

// RedirectCheck vets a redirect target before it is fetched.
type RedirectCheck func(*url.URL) error

var errRedirectNotAllowed = errors.New(errors.ErrCodeUpstreamError, "redirect refused")

func noAutoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// send performs req and follows redirects itself, so each hop is vetted and, once the
// host changes, dialed through the guard that refuses private addresses.
func (c *Client) send(req *http.Request, check RedirectCheck) (*http.Response, error) {
	origin := req.URL.Host
	cur := req
	httpClient := c.client
	for hop := 0; ; hop++ {
		resp, err := httpClient.Do(cur)
		if err != nil {
			return nil, err
		}
		loc := resp.Header.Get("Location")
		if !isRedirectStatus(resp.StatusCode) || loc == "" {
			return resp, nil
		}
		_ = resp.Body.Close() // #nosec G104 -- Cleanup, error not critical
		if hop >= MaxRedirects {
			return nil, errors.Wrap(errRedirectNotAllowed, errors.ErrCodeUpstreamError, "too many redirects")
		}
		next, err := cur.URL.Parse(loc)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeUpstreamError, "invalid redirect location")
		}
		if next.Scheme != "http" && next.Scheme != "https" {
			return nil, errors.Wrap(errRedirectNotAllowed, errors.ErrCodeUpstreamError, "redirect to non-http scheme")
		}
		if check != nil {
			if err := check(next); err != nil {
				return nil, errors.Wrap(err, errors.ErrCodeUpstreamError, "redirect target not allowed")
			}
		}
		clone := cur.Clone(cur.Context())
		clone.URL = next
		clone.Host = ""
		if next.Host != cur.URL.Host {
			clone.Header.Del("Authorization")
			clone.Header.Del("Cookie")
		}
		cur = clone
		if next.Host != origin {
			httpClient = c.hopClient
		}
	}
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// carrierGradeNAT is 100.64.0.0/10, which net.IP.IsPrivate does not cover.
var carrierGradeNAT = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// refusePrivateAddress runs after DNS resolution, so a name cannot rebind to an internal address.
func refusePrivateAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || carrierGradeNAT.Contains(ip) {
		return fmt.Errorf("refusing to connect to non-public address %s", host)
	}
	return nil
}
