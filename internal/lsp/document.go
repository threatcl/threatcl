package lsp

import (
	"sync"

	protocol "github.com/tliron/glsp/protocol_3_16"
)

// document is the server's copy of an open text document.
type document struct {
	text    []byte
	version int32
}

// store is the in-memory set of open documents, keyed by URI. glsp dispatches
// requests serially per connection, but the mutex is cheap insurance against a
// future concurrent dispatcher.
type store struct {
	mu   sync.RWMutex
	docs map[protocol.DocumentUri]document
}

func newStore() *store {
	return &store{docs: map[protocol.DocumentUri]document{}}
}

func (s *store) set(uri protocol.DocumentUri, text []byte, version int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[uri] = document{text: text, version: version}
}

// get returns the document's current text and whether it is open.
func (s *store) get(uri protocol.DocumentUri) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.docs[uri]
	return doc.text, ok
}

func (s *store) delete(uri protocol.DocumentUri) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, uri)
}
