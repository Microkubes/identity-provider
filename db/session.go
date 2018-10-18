package db

import (
	"net/http"

	"github.com/JormungandrK/backends"

	"github.com/crewjam/saml"
	"github.com/goadesign/goa"
)

// GetSession returns the *Session for this request.
// If a session cookie already exists and represents a valid session, then the session is returned
func (s *IDPStore) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) (*saml.Session, error) {
	if sessionCookie, err := r.Cookie("session"); err == nil {
		session := &saml.Session{}
		id := sessionCookie.Value

		_, err := s.Sessions.GetOne(backends.NewFilter().Match("id", id), session)
		if err != nil {
			if backends.IsErrNotFound(err) {
				return nil, goa.ErrNotFound("session not found in database")
			}

			return nil, goa.ErrInternal(err)
		}

		if saml.TimeNow().After(session.ExpireTime) {
			return nil, goa.ErrInvalidRequest("session has expired")
		}

		return session, nil
	}

	return nil, goa.ErrNotFound("session is not set in the request")
}

// AddSession adds new session in DB
func (s *IDPStore) AddSession(session *saml.Session) error {
	if _, err := s.Sessions.Save(session, nil); err != nil {
		return err
	}

	return nil
}

// DeleteSession deletes session by sessionID which is cookie value
func (s *IDPStore) DeleteSession(sessionID string) error {
	err := s.Sessions.DeleteOne(backends.NewFilter().Match("id", sessionID))
	if err != nil {
		if backends.IsErrNotFound(err) {
			return goa.ErrNotFound("session not found")
		}

		return goa.ErrInternal(err)
	}

	return nil
}

// GetSessions returns all sessions
func (s *IDPStore) GetSessions() (*[]saml.Session, error) {
	var sessions []saml.Session
	var typeHint map[string]interface{}

	items, err := s.Sessions.GetAll(nil, typeHint, "", "", 0, 0)
	if err != nil {
		return nil, goa.ErrInternal(err)
	}

	if err := backends.MapToInterface(items, &sessions); err != nil {
		return nil, goa.ErrInternal(err)
	}

	if len(sessions) == 0 {
		return nil, goa.ErrNotFound("no sessions found!")
	}

	return &sessions, nil
}
