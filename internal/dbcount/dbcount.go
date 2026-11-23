// Package dbcount counts the SQL statements a GORM handle runs, for query-count tests.
package dbcount

import (
	"context"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Counter holds the number of statements seen since the last Reset.
type Counter struct {
	n atomic.Int64
}

// Attach returns a session of db that counts every statement it executes. It
// swaps the logger instead of registering callbacks, because callback
// registration is not safe while other goroutines already run queries.
// GORM runs a subquery as a dry run with a discarded logger, so subqueries do not count.
func Attach(db *gorm.DB) (*gorm.DB, *Counter) {
	c := &Counter{}
	return db.Session(&gorm.Session{Logger: &countingLogger{Interface: logger.Discard, c: c}}), c
}

// Reset zeroes the count.
func (c *Counter) Reset() { c.n.Store(0) }

// Count returns the statements counted since the last Reset.
func (c *Counter) Count() int { return int(c.n.Load()) }

type countingLogger struct {
	logger.Interface
	c *Counter
}

func (l *countingLogger) LogMode(logger.LogLevel) logger.Interface { return l }

func (l *countingLogger) Trace(context.Context, time.Time, func() (string, int64), error) {
	l.c.n.Add(1)
}
