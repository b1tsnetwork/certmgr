package main

import (
	"context"
	"log"
	"time"
)

func (a *App) scheduleDue() {
	a.mu.RLock()
	now := time.Now()
	ids := make([]string, 0)
	for _, t := range a.state.Targets {
		if a.running[t.ID] {
			continue
		}
		if t.LastCheck == nil || !now.Before(t.LastCheck.CheckedAt.Add(time.Duration(t.IntervalMinutes)*time.Minute)) {
			ids = append(ids, t.ID)
		}
	}
	a.mu.RUnlock()
	for _, id := range ids {
		a.queueCheck(id)
	}
}

func (a *App) scheduler(ctx context.Context) {
	a.scheduleDue()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scheduleDue()
		}
	}
}

func (a *App) queueCheck(id string) bool {
	a.mu.Lock()
	t := findTarget(&a.state, id)
	if t == nil || a.running[id] {
		a.mu.Unlock()
		return false
	}
	target := *t
	settings := a.state.Settings
	roots := selectRoots(target, append([]RootCA(nil), a.state.Roots...))
	a.running[id] = true
	a.mu.Unlock()

	go func() {
		a.sem <- struct{}{}
		defer func() { <-a.sem }()
		result := checkTarget(context.Background(), target, settings, roots)
		a.mu.Lock()
		defer a.mu.Unlock()
		delete(a.running, id)
		current := findTarget(&a.state, id)
		if current == nil || current.Revision != target.Revision {
			return
		}
		current.LastCheck = &result
		if err := a.saveLocked(); err != nil {
			log.Printf("Ergebnis für %q konnte nicht gespeichert werden: %v", target.Name, err)
		}
	}()
	return true
}

func (a *App) isRunning(id string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running[id]
}
