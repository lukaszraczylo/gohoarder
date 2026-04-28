// Package events defines the cross-package event broadcaster interface.
//
// Sub-systems such as cache and scanner emit lifecycle events but must
// not import pkg/websocket directly (would create circular import once
// websocket grows callers in those packages or in app wiring).
//
// The Broadcaster contract is intentionally minimal: a single method
// that accepts an event type string and an arbitrary payload. The
// concrete implementation (websocket.Server) decides how to marshal
// and dispatch the payload.
package events

// Broadcaster is the minimal contract sub-systems use to publish events.
//
// Implementations MUST be safe for concurrent use and MUST NOT block
// the caller (callers expect fire-and-forget semantics). If the
// underlying transport is full or unavailable, implementations should
// drop the event and log, never block or panic.
type Broadcaster interface {
	// BroadcastEvent publishes an event of the given type with the
	// supplied payload. Payload is typically map[string]any but
	// implementations may accept arbitrary serialisable values.
	BroadcastEvent(eventType string, payload any)
}
