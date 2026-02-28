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

package oast

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/dguerri/oast-mcp/internal/store"
)

// Mock implements Interacter for use in unit tests.
// Call InjectEvent to simulate an incoming OAST callback.
type Mock struct {
	Sink EventSink
	Zone string
	seq  atomic.Int64
}

func NewMock(sink EventSink, zone string) *Mock {
	return &Mock{Sink: sink, Zone: zone}
}

func (m *Mock) NewSession(_ context.Context, _, _ string) (*Endpoints, error) {
	id := m.seq.Add(1)
	corrID := fmt.Sprintf("mockid%06d", id)
	return &Endpoints{
		CorrelationID: corrID,
		DNS:           fmt.Sprintf("%s.%s", corrID, m.Zone),
		HTTP:          fmt.Sprintf("http://%s.%s", corrID, m.Zone),
		HTTPS:         fmt.Sprintf("https://%s.%s", corrID, m.Zone),
	}, nil
}

func (m *Mock) StartPolling(_ context.Context) error { return nil }
func (m *Mock) Stop()                                {}

// InjectEvent simulates an OAST callback arriving at the server.
func (m *Mock) InjectEvent(ctx context.Context, ev *store.Event) error {
	return m.Sink.SaveEvent(ctx, ev)
}
