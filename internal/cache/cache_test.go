package cache

import (
	"sync"
	"testing"
	"time"
)

func TestCache_SetAndGet(t *testing.T) {
	c := New[string](5*time.Second, 100)

	c.Set("key1", "value1")
	c.Set("key2", "value2")

	v, ok := c.Get("key1")
	if !ok || v != "value1" {
		t.Errorf("expected value1, got %s (ok=%v)", v, ok)
	}

	v, ok = c.Get("key2")
	if !ok || v != "value2" {
		t.Errorf("expected value2, got %s (ok=%v)", v, ok)
	}
}

func TestCache_GetMissing(t *testing.T) {
	c := New[string](5*time.Second, 100)

	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestCache_Expiration(t *testing.T) {
	c := New[string](50*time.Millisecond, 100)

	c.Set("key1", "value1")

	// Should exist immediately
	v, ok := c.Get("key1")
	if !ok || v != "value1" {
		t.Errorf("expected value1 immediately, got %s (ok=%v)", v, ok)
	}

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	_, ok = c.Get("key1")
	if ok {
		t.Error("expected expired entry to not be found")
	}
}

func TestCache_Delete(t *testing.T) {
	c := New[string](5*time.Second, 100)

	c.Set("key1", "value1")
	c.Delete("key1")

	_, ok := c.Get("key1")
	if ok {
		t.Error("expected deleted entry to not be found")
	}
}

func TestCache_Overwrite(t *testing.T) {
	c := New[string](5*time.Second, 100)

	c.Set("key1", "value1")
	c.Set("key1", "value2")

	v, ok := c.Get("key1")
	if !ok || v != "value2" {
		t.Errorf("expected value2, got %s (ok=%v)", v, ok)
	}
}

func TestCache_StructValues(t *testing.T) {
	type meta struct {
		Name   string
		Labels map[string]string
	}

	c := New[*meta](5*time.Second, 100)

	m := &meta{Name: "test", Labels: map[string]string{"env": "prod"}}
	c.Set("container1", m)

	got, ok := c.Get("container1")
	if !ok {
		t.Fatal("expected to find entry")
	}
	if got.Name != "test" {
		t.Errorf("expected name test, got %s", got.Name)
	}
	if got.Labels["env"] != "prod" {
		t.Errorf("expected label env=prod, got %v", got.Labels)
	}
}

func TestCache_Concurrent(t *testing.T) {
	c := New[int](5*time.Second, 1000)

	var wg sync.WaitGroup
	// Writers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Set(string(rune('a'+i%26)), i)
		}(i)
	}
	// Readers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Get(string(rune('a' + i%26)))
		}(i)
	}
	wg.Wait()
}

func TestCache_MaxSize(t *testing.T) {
	c := New[string](5*time.Second, 5)

	// Fill to capacity
	for i := 0; i < 5; i++ {
		c.Set(string(rune('a'+i)), "value")
	}

	// Add one more — should not panic (eviction happens)
	c.Set("overflow", "value")

	// The overflow value should be retrievable
	v, ok := c.Get("overflow")
	if !ok || v != "value" {
		t.Errorf("expected overflow value, got %s (ok=%v)", v, ok)
	}
}

func TestCache_CleanupRuns(t *testing.T) {
	c := New[string](50*time.Millisecond, 100)

	c.Set("key1", "value1")

	// Wait for cleanup cycle
	time.Sleep(120 * time.Millisecond)

	_, ok := c.Get("key1")
	if ok {
		t.Error("expected cleanup to have removed expired entry")
	}
}
