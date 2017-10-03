package db

import (
	"fmt"
	"net/http"

	"gopkg.in/mgo.v2/bson"

	"github.com/crewjam/saml"
	"github.com/goadesign/goa"
)

// GetSession returns the *Session for this request.
// If a session cookie already exists and represents a valid session, then the session is returned
func (m *MongoCollections) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) (*saml.Session, error) {
	if sessionCookie, err := r.Cookie("session"); err == nil {
		session := &saml.Session{}
		id := sessionCookie.Value
		query := bson.M{"id": bson.M{"$eq": id}}

		if err := m.Sessions.Find(query).One(session); err != nil {
			if err.Error() == "not found" {
				return nil, goa.ErrNotFound("session not found in database")
			}
			return nil, goa.ErrInternal(err)
		}

		if saml.TimeNow().After(session.ExpireTime) {
			// if err := m.DeleteSession(id); err != nil {
			// 	return nil, goa.ErrInternal(err)
			// }
			return nil, goa.ErrInvalidRequest("session has expired")
		}

		return session, nil
	}

	return nil, goa.ErrNotFound("session is not set in the request")
}

// AddSession adds new session in DB
func (m *MongoCollections) AddSession(session *saml.Session) error {
	if err := m.Sessions.Insert(session); err != nil {
		return err
	}

	return nil
}

// DeleteSession deletes session by sessionID which is cookie value
func (m *MongoCollections) DeleteSession(sessionID string) error {
	fmt.Println("Session: ", sessionID)
	selector := bson.M{"id": bson.M{"$eq": sessionID}}
	err := m.Sessions.Remove(selector)
	if err != nil {
		if err.Error() == "not found" {
			return goa.ErrNotFound("session not found")
		} else {
			return goa.ErrInternal(err)
		}
	}

	return nil
}

// GetSessions returns all sessions
func (m *MongoCollections) GetSessions() (*[]saml.Session, error) {
	var sessions []saml.Session
	if err := m.Sessions.Find(nil).All(&sessions); err != nil {
		return nil, goa.ErrInternal(err)
	}

	if len(sessions) == 0 {
		return nil, goa.ErrNotFound("no sessions found!")
	}

	return &sessions, nil
}
