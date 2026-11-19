package goproxy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHttpDoesNotForwardConnectionClose verifies that the plain HTTP proxy
// path strips "Connection: close" before forwarding to the upstream server.
// Without the r.Close fix, RemoveProxyHeaders deletes the Connection header
// but leaves r.Close = true, so Go's serializer re-injects it on the wire.
func TestHttpDoesNotForwardConnectionClose(t *testing.T) {
	type upstreamObs struct {
		close      bool
		connection string
	}
	ch := make(chan upstreamObs, 1)

	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ch <- upstreamObs{
				close:      r.Close,
				connection: r.Header.Get("Connection"),
			}
			w.WriteHeader(http.StatusOK)
		}))
	defer upstream.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}}

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, upstream.URL, http.NoBody)
	require.NoError(t, err)
	req.Close = true

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	obs := <-ch
	assert.False(t, obs.close,
		"upstream saw r.Close == true; Connection: close leaked")
	assert.Empty(t, obs.connection,
		"upstream received Connection: %s; hop-by-hop header leaked",
		obs.connection)
}
