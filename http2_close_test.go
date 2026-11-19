package goproxy_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMitmH2UpstreamDoesNotSeeClose is a regression guard:
// when the proxy speaks HTTP/2 to the upstream, r.Close must be false
// because HTTP/2 has no Connection field (RFC 9113 §8.2.2).
//
func TestMitmH2UpstreamDoesNotSeeClose(t *testing.T) {
	type upstreamObs struct {
		protoMajor int
		close      bool
		connection string
	}
	ch := make(chan upstreamObs, 1)

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ch <- upstreamObs{
				protoMajor: r.ProtoMajor,
				close:      r.Close,
				connection: r.Header.Get("Connection"),
			}
			w.WriteHeader(http.StatusOK)
		}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, upstream.URL, http.NoBody)
	require.NoError(t, err)
	req.Close = true

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	obs := <-ch
	assert.Equal(t, 2, obs.protoMajor,
		"upstream should see HTTP/2 request")
	assert.False(t, obs.close,
		"upstream r.Close must be false for HTTP/2 (RFC 9113 §8.2.2)")
	assert.Empty(t, obs.connection,
		"upstream must not see Connection header over HTTP/2")
}
