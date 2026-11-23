package gormstore

import "testing"

func TestCloseIsIdempotent(t *testing.T) {
	store := openFileStore(t, true)
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
