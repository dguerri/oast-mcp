// Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ratelimit provides per-tenant token-bucket rate limiting.
package ratelimit

import (
	"sync"

	"golang.org/x/time/rate"
)

// Limiter maintains a separate token-bucket rate limiter per tenant.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	r       rate.Limit
	b       int
}

// New creates a Limiter with rps tokens per second and burst size b.
func New(rps float64, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*rate.Limiter),
		r:       rate.Limit(rps),
		b:       burst,
	}
}

func (l *Limiter) bucket(tenantID string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.buckets[tenantID]; ok {
		return lim
	}
	lim := rate.NewLimiter(l.r, l.b)
	l.buckets[tenantID] = lim
	return lim
}

// Allow reports whether an event for tenantID may proceed without blocking.
func (l *Limiter) Allow(tenantID string) bool {
	return l.bucket(tenantID).Allow()
}

