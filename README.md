# Go HTTPS 

**This is work-in-progress.**

Package https wraps Go's package http and ensures connections are secure and
using up-to-date transports.

Currently, a simple client is provided. It limits the client to a few safe
ciphers and encourages the use of stronger elliptic-curves first. It also
ensures that requests are always HTTPS and they never get redirected to plain
HTTP.

To instantiate a new HTTPS client:

```
client := https.NewClient()
// Use it as you would use http.Client.
resp, err := client.Get("https://example.com")
```

To start a new HTTPS server:

```
// Register some handlers:
mux := http.NewServeMux()
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    w.Write("Hello world")
})

// Secure it with a TLS certificate using Let's  Encrypt:
m := autocert.Manager{
	Prompt:     autocert.AcceptTOS,
	Cache:      autocert.DirCache("/etc/acme-cache/"),
	Email:      "me@example.com",
	HostPolicy: autocert.HostWhitelist("example.com"),
}

// Start a secure server:
https.StartSecureServer(mux, m.GetCertificate)
```

TODOs

1. provide a list of trustworthy root CAs (with proven certificate transparency
logs).




