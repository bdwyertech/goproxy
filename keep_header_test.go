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

// TestKeepHeaderPreservation verifies that KeepHeader, absent-Connection, and
// keep-alive behaviors are unchanged.  All cases verify baseline behavior

func TestKeepHeaderPreservation(t *testing.T) {
	type upstreamObs struct {
		close      bool
		connection string
	}

	cases := []struct {
		name           string
		keepHeader     bool
		setClose       bool   // sets req.Close = true on the client request
		connectionVal  string // explicit Connection header value ("" = don't set)
		wantClose      bool
		wantConnection string // expected Connection header at upstream ("" = absent)
	}{
		// KeepHeader=true skips RemoveProxyHeaders; upstream still sees
		// Connection: close and r.Close is unchanged.
		{
			name:           "keep header with connection close",
			keepHeader:     true,
			setClose:       true,
			wantClose:      true,
			wantConnection: "close",
		},
		// KeepHeader=true with a non-close request — upstream sees
		// r.Close == false and no Connection header injected.
		{
			name:       "keep header without connection close",
			keepHeader: true,
			wantClose:  false,
		},
		// KeepHeader=false, no Connection header on the request —
		// upstream must NOT see a Connection header injected, r.Close stays false.
		{
			name:       "no connection header",
			keepHeader: false,
			wantClose:  false,
		},
		// KeepHeader=false, Connection: keep-alive — the header is
		// stripped by RemoveProxyHeaders and r.Close stays false.
		{
			name:          "keep-alive stripped",
			keepHeader:    false,
			connectionVal: "keep-alive",
			wantClose:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			proxy.KeepHeader = tc.keepHeader
			proxySrv := httptest.NewServer(proxy)
			defer proxySrv.Close()

			proxyURL, err := url.Parse(proxySrv.URL)
			require.NoError(t, err)

			client := &http.Client{Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}}
			defer client.CloseIdleConnections()

			req, err := http.NewRequestWithContext(
				context.Background(), http.MethodGet, upstream.URL, http.NoBody)
			require.NoError(t, err)
			req.Close = tc.setClose
			if tc.connectionVal != "" {
				req.Header.Set("Connection", tc.connectionVal)
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			obs := <-ch
			assert.Equal(t, tc.wantClose, obs.close,
				"upstream r.Close mismatch")
			assert.Equal(t, tc.wantConnection, obs.connection,
				"upstream Connection header mismatch")
		})
	}
}
