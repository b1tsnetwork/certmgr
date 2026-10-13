package main

import (
	"net/http"
	"strings"
)

// Browsable public area: certificate metadata and public artifacts only.
// The service inventory, token list and private material are never exposed.
func (s *server) publicIndex(w http.ResponseWriter, r *http.Request) {
	d := viewData{Title: "Öffentliche Zertifikate"}
	for _, def := range s.catalog.snapshot().Certificates {
		if !def.Enabled {
			continue
		}
		m, err := s.vault.load(def.Name, "")
		if err != nil {
			continue
		}
		d.Certificates = append(d.Certificates, certificateView{
			Name: def.Name, Label: def.Label, Version: m.Version,
			NotAfter: m.NotAfter.Local().Format("02.01.2006 15:04"),
			DNSNames: strings.Join(m.DNSNames, ", "),
		})
	}
	s.template(w, 200, "public-index.html", d)
}
func (s *server) publicDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.configured(name) {
		http.NotFound(w, r)
		return
	}
	m, err := s.vault.load(name, "")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	def, _ := s.catalog.certificate(name)
	d := viewData{Title: "Öffentliches Zertifikat · " + name, Certificate: certificateView{Name: name, Label: def.Label, Version: m.Version, NotAfter: m.NotAfter.Local().Format("02.01.2006 15:04"), DNSNames: strings.Join(m.DNSNames, ", "), Fingerprint: m.Fingerprint}}
	for _, a := range m.Artifacts {
		if !a.Private {
			d.PublicArtifacts = append(d.PublicArtifacts, a)
		}
	}
	s.template(w, 200, "public-detail.html", d)
}
