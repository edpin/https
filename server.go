// Copyright 2017 Eduardo Pinheiro (edpin@edpin.com). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package https

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// StartSecureServer starts an HTTPS server with a Handler and an autocert
// manager. The HTTPS server started enables HTST by default to ensure maximum
// protection (see
// https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet).
// StartSecureServer also starts an HTTP server that redirects all requests to
// their HTTPS counterpart and immediately terminates all connections.
func StartSecureServer(h http.Handler, m *autocert.Manager) {
	s := NewSecureServer(m)
	s.Handler = NewHSTS(h)
	go func() {
		// Redirect regular HTTP requests to HTTPS.
		insecure := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Connection", "close")
				url := "https://" + req.Host + req.URL.String()
				http.Redirect(w, req, url, http.StatusMovedPermanently)
			}),
		}
		log.Fatal(insecure.ListenAndServe())
	}()
	log.Fatal(s.ListenAndServeTLS("", ""))
}

type hstsHandler struct {
	h http.Handler
}

// NewSecureServer returns a new HTTP server with strict security settings.
func NewSecureServer(m *autocert.Manager) *http.Server {
	t := m.TLSConfig()
	t.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	t.MinVersion = tls.VersionTLS12
	t.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP521,
		tls.CurveP384,
		tls.CurveP256,
	}

	return &http.Server{
		Addr:              ":https",
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         t,
	}
}

// NewHSTS returns an HTTP handler that sets HSTS headers on all requests.
func NewHSTS(h http.Handler) http.Handler {
	return hstsHandler{
		h: h,
	}
}

// ServeHTTP implements http.Handler.
func (h hstsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.h.ServeHTTP(w, r)
}
