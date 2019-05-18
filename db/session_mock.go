package db

import (
	"net/http"

	"github.com/crewjam/saml"
	"github.com/keitaroinc/goa"
)

// GetSession return saml Session
func (db *DB) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) (*saml.Session, error) {
	if sessionCookie, err := r.Cookie("session"); err == nil {
		id := sessionCookie.Value
		return db.sessions[id], nil
	}

	return nil, goa.ErrNotFound("session not found")
}

// AddSession adds new sessions
func (db *DB) AddSession(session *saml.Session) error {
	db.sessions[session.ID] = session
	return nil
}

// DeleteSession deletes session
func (db *DB) DeleteSession(sessionID string) error {
	if sessionID == "not-found" {
		return goa.ErrNotFound("session not found")
	}
	if sessionID == "internal-server-error" {
		return goa.ErrInternal("Internal Server Error")
	}

	return nil
}

// GetSessions lists all session
func (db *DB) GetSessions() (*[]saml.Session, error) {
	if _, ok := db.sessions["not-found"]; ok {
		delete(db.sessions, "not-found")
		return nil, goa.ErrNotFound("no sessions found")
	}
	if _, ok := db.sessions["internal-server-error"]; ok {
		delete(db.sessions, "internal-server-error")
		return nil, goa.ErrInternal("Internal Server Error")
	}

	var sessions []saml.Session
	var session *saml.Session

	for _, value := range db.sessions {
		sessions = append(sessions, *value)
		session = value
	}
	db.sessions["not-found"] = session
	db.sessions["internal-server-error"] = session

	return &sessions, nil
}
