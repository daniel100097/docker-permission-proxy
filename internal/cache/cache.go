// Package cache provides a TTL cache for container metadata and exec-id mappings.
package cache

import (
	"sync"
	"time"
)

// Entry holds a cached value with expiration time.
type Entry[T any] struct {
	Value     T
	ExpiresAt time.Time
}

// TTLCache is a generic TTL-based cache.
type TTLCache[T any] struct {
	mu      sync.RWMutex
	items   map[string]Entry[T]
	ttl     time.Duration
	maxSize int
}

// New creates a new TTLCache with the given TTL and max size.
func New[T any](ttl time.Duration, maxSize int) *TTLCache[T] {
	c := &TTLCache[T]{
		items:   make(map[string]Entry[T]),
		ttl:     ttl,
		maxSize: maxSize,
	}
	// Background cleanup every TTL period
	go c.cleanup()
	return c
}

// Set stores a value in the cache.
func (c *TTLCache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if over max size
	if len(c.items) >= c.maxSize {
		c.evictExpired()
		if len(c.items) >= c.maxSize {
			c.evictAny()
		}
	}

	c.items[key] = Entry[T]{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// Get retrieves a value from the cache. Returns the value and whether it was found.
func (c *TTLCache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.items[key]
	if !ok {
		var zero T
		return zero, false
	}
	if time.Now().After(entry.ExpiresAt) {
		var zero T
		return zero, false
	}
	return entry.Value, true
}

// Delete removes an entry from the cache.
func (c *TTLCache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *TTLCache[T]) evictExpired() {
	now := time.Now()
	for k, v := range c.items {
		if now.After(v.ExpiresAt) {
			delete(c.items, k)
		}
	}
}

func (c *TTLCache[T]) evictAny() {
	for k := range c.items {
		delete(c.items, k)
		return
	}
}

func (c *TTLCache[T]) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		c.evictExpired()
		c.mu.Unlock()
	}
}
