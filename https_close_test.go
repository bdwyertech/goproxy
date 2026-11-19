package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// After a MITM'd response, the proxy must close the client connection when
// the request or the response carries "Connection: close". A client that
// doesn't read the body of such a response waits for the close to finish.
func TestMitmConnectionClose(t *testing.T) {
	cases := []struct {
		name           string
		requestClose   bool
		responseClose  bool
		directResponse bool
	}{
		{name: "keep-alive"},
		{name: "request close", requestClose: true},
		{name: "response close", responseClose: true},
		// A handler that returns a canned response also returns a nil request,
		// so the close has to come from the client's original request.
		{name: "request close with direct response", requestClose: true, directResponse: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.False(t, tc.directResponse, "direct response unexpectedly reached the upstream server")
				// RemoveProxyHeaders must strip the header and reset r.Close;
				// otherwise Go re-injects "Connection: close" on the wire.
				assert.False(t, r.Close,
					"upstream saw r.Close == true; Connection: close leaked through MITM proxy")
				assert.Empty(t, r.Header.Get("Connection"),
					"upstream received Connection: %s; hop-by-hop header leaked",
					r.Header.Get("Connection"))
				if tc.responseClose {
					w.Header().Set("Connection", "close")
				}
				_, _ = io.WriteString(w, "ok")
			}))
			defer upstream.Close()

			proxy := goproxy.NewProxyHttpServer()
			proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
			if tc.directResponse {
				proxy.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, "ok")
				})
			}
			proxySrv := httptest.NewServer(proxy)
			defer proxySrv.Close()

			// A raw client is required here: http.Transport closes the connection
			// itself on "Connection: close", so it can't tell whether the proxy did.
			conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxySrv.Listener.Addr().String())
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

			connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, upstream.URL, nil)
			require.NoError(t, err)
			require.NoError(t, connectReq.Write(conn))
			connectResp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, connectResp.StatusCode)

			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			require.NoError(t, tlsConn.HandshakeContext(context.Background()))
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, http.NoBody)
			require.NoError(t, err)
			req.Close = tc.requestClose
			require.NoError(t, req.Write(tlsConn))

			reader := bufio.NewReader(tlsConn)
			resp, err := http.ReadResponse(reader, req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "ok", string(body))

			// The proxy must echo Connection: close to
			// the client when either side asked for it (RFC 9112 §9.6).
			if tc.requestClose || tc.responseClose {
				assert.True(t, resp.Close,
					"proxy response should signal connection close (RFC 9112 §9.6)")
			}

			require.NoError(t, tlsConn.SetReadDeadline(time.Now().Add(time.Second)))
			_, err = reader.ReadByte()
			if tc.requestClose || tc.responseClose {
				require.ErrorIs(t, err, io.EOF, "proxy kept the connection open after Connection: close")
			} else {
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				assert.True(t, netErr.Timeout(), "proxy closed a keep-alive connection: %v", err)
			}
		})
	}
}

// TestMitmReusesUpstreamConnOnRequestClose verifies that the proxy's transport
// reuses upstream connections even when the client sends "Connection: close".
// Without the r.Close fix, Connection: close leaks to the
// upstream, which closes the connection, defeating keep-alive pooling.
func TestMitmReusesUpstreamConnOnRequestClose(t *testing.T) {
	var newConns atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	upstream.StartTLS()
	defer upstream.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	for i := range 2 {
		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet, upstream.URL, http.NoBody)
		require.NoError(t, err, "request %d", i)
		req.Close = true

		resp, err := client.Do(req)
		require.NoError(t, err, "request %d", i)
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	assert.Equal(t, int32(1), newConns.Load(),
		"proxy opened %d upstream connections; expected 1 "+
			"(Connection: close leaked, defeating pooling)",
		newConns.Load())
}
