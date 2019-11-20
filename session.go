package main

import (
	"fmt"
	"github.com/satori/go.uuid"
	"net/http"
	"time"
)

func getUserFromSession(req *http.Request) result {
	// get cookie
	c, _ := req.Cookie("session")
	var u result
	if len(dbSessions) != 0 {
		if s, ok := dbSessions[c.Value]; ok {
			u = s.user
			// update last activity
			s.LastActivity = time.Now()
		}
	}
	return u
}

func createCookie(w http.ResponseWriter) string {
	sID, _ := uuid.NewV4()
	c := &http.Cookie{
		Name:  "session",
		Value: sID.String(),
	}
	http.SetCookie(w, c)
	return sID.String()
}

func createSession(sID string, u result) {
	s := session{u, time.Now()}
	dbSessions[sID] = &s
}

func removeCookie(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)
}

func expireOldSessions() {
	for {
		for k, v := range dbSessions {
			if time.Since(v.LastActivity) > (time.Second*time.Duration(sessionLength)) {
				fmt.Println("User session expired:", dbSessions[k])
				delete(dbSessions, k)
			}
		}
		fmt.Println("Expiring old sessions")
		time.Sleep(1000 * time.Millisecond)
	}
}
