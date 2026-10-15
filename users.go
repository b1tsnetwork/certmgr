package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,39}$`)

func validRole(role string) bool { return role == "admin" || role == "editor" || role == "viewer" }
func (a *App) usersPage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Benutzerverwaltung", "users", s, st)
	d.Users = st.Users
	switch r.URL.Query().Get("notice") {
	case "created":
		d.Notice = "Benutzer angelegt."
	case "updated":
		d.Notice = "Benutzer aktualisiert; bestehende Sitzungen wurden beendet."
	case "deleted":
		d.Notice = "Benutzer gelöscht."
	}
	render(w, "users", d)
}
func userError(w http.ResponseWriter, r *http.Request, e error) {
	http.Error(w, e.Error(), http.StatusBadRequest)
}
func (a *App) createUser(w http.ResponseWriter, r *http.Request, _ session) {
	username := strings.TrimSpace(r.FormValue("username"))
	role := r.FormValue("role")
	if !usernamePattern.MatchString(username) || !validRole(role) {
		userError(w, r, fmt.Errorf("Benutzername: 3–40 Zeichen (Buchstaben, Ziffern, ._-); Rolle ungültig"))
		return
	}
	if r.FormValue("password") != r.FormValue("confirm_password") {
		userError(w, r, fmt.Errorf("Passwörter stimmen nicht überein"))
		return
	}
	h, err := hashPassword(r.FormValue("password"))
	if err != nil {
		userError(w, r, err)
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "ID-Fehler", 500)
		return
	}
	a.mu.Lock()
	for _, u := range a.state.Users {
		if strings.EqualFold(u.Username, username) {
			a.mu.Unlock()
			userError(w, r, fmt.Errorf("Benutzername bereits vergeben"))
			return
		}
	}
	a.state.Users = append(a.state.Users, User{ID: id, Username: username, Role: role, Password: h, CreatedAt: time.Now()})
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/users?notice=created", 303)
}
func (a *App) changeUserRole(w http.ResponseWriter, r *http.Request, s session) {
	id, role := r.PathValue("id"), r.FormValue("role")
	if !validRole(role) {
		userError(w, r, fmt.Errorf("Ungültige Rolle"))
		return
	}
	if id == s.userID {
		userError(w, r, fmt.Errorf("Eigene Rolle kann nicht geändert werden"))
		return
	}
	a.mu.Lock()
	found := false
	for i := range a.state.Users {
		if a.state.Users[i].ID == id {
			a.state.Users[i].Role = role
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	err := a.saveLocked()
	if err == nil {
		a.revokeUserSessionsLocked(id)
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/users?notice=updated", 303)
}
func (a *App) resetUserPassword(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	if r.FormValue("password") != r.FormValue("confirm_password") {
		userError(w, r, fmt.Errorf("Passwörter stimmen nicht überein"))
		return
	}
	h, err := hashPassword(r.FormValue("password"))
	if err != nil {
		userError(w, r, err)
		return
	}
	a.mu.Lock()
	found := false
	for i := range a.state.Users {
		if a.state.Users[i].ID == id {
			a.state.Users[i].Password = h
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	err = a.saveLocked()
	if err == nil {
		a.revokeUserSessionsLocked(id)
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/users?notice=updated", 303)
}
func (a *App) revokeUserSessionsLocked(id string) {
	for token, s := range a.sessions {
		if s.userID == id {
			delete(a.sessions, token)
		}
	}
}
func (a *App) deleteUser(w http.ResponseWriter, r *http.Request, s session) {
	id := r.PathValue("id")
	if id == s.userID {
		userError(w, r, fmt.Errorf("Eigenes Konto kann nicht gelöscht werden"))
		return
	}
	a.mu.Lock()
	found := false
	for i, u := range a.state.Users {
		if u.ID == id {
			a.state.Users = append(a.state.Users[:i], a.state.Users[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	err := a.saveLocked()
	if err == nil {
		a.revokeUserSessionsLocked(id)
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/users?notice=deleted", 303)
}
