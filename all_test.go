// Copyright 2017 Eduardo Pinheiro (edpin@edpin.com). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package https

import (
	"net/url"
	"testing"
)

func TestClientHTTPS(t *testing.T) {
	client := NewClient()

	_, err := client.Get("http://localhost")
	if err == nil {
		t.Fatalf("Expected error, got none")
	}
	expected := "not secure http protocol"
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err)
	}

	_, err = client.Post("http://foo.com", "application/json", nil)
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err)
	}

	data := url.Values{}
	_, err = client.PostForm("http://bar.com", data)
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err)
	}

	_, err = client.Head("http://headlessjohn.org")
	if err.Error() != expected {
		t.Fatalf("Expected error %q, got %q", expected, err)
	}
}
