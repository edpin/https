// Copyright 2017 Eduardo Pinheiro (edpin@edpin.com). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package https wraps package http and ensures connections are secure and
// using up-to-date transports.
package https

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client wraps an http.Client and ensures all connections are HTTPS and on the
// most recent TLS version with strong ciphers.
type Client struct {
	*http.Client
}

func NewClient() *Client {
	tlsConfig := tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		// Prefer this order of ciphers.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// required by HTTP-2.
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// To be explicit about our choice above.
		PreferServerCipherSuites: false,
		MinVersion:               tls.VersionTLS12,
		// TODO: roll our own root CA list. Limit to those publishing
		// certificate transparency (see
		// https://www.certificate-transparency.org/).
	}
	return &Client{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tlsConfig,
			},
			CheckRedirect: checkRedirect,
		},
	}
}

// Do overrides http.Client.Do. We just ensure the request is an HTTPS request.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("not secure http protocol")
	}
	// Call the default Client.
	return c.Client.Do(req)
}

// Get overrides http.Get.
func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post overrides http.Post.
func (c *Client) Post(url string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	return c.Do(req)
}

// PostFrom overrides http.PostFrom.
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (c *Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("redirected to non-https protocol")
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}
