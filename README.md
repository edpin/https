# Go HTTPS 

**This is work-in-progress.**

Package https wraps Go's package http and ensures connections are secure and
using up-to-date transports.

Currently, a simple client is provided. It limits the client to a few safe
ciphers and encourages the use of stronger elliptic-curves first. It also
ensures that requests are always HTTPS and they never get redirected to plain
HTTP.

To instantiate a new https.Client:

```
client := https.NewClient()
// Use it as you would use http.Client.
resp, err := client.Get("https://example.com")
```

TODOs

1. add similar wrapper for the server side.
2. provide a list of trustworthy root CAs (with proven certificate transparency
logs).




