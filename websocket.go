package goproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aus/proxyplease"
	"github.com/gorilla/websocket"
)

func headerContains(header http.Header, name string, value string) bool {
	for _, v := range header[name] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(value, strings.TrimSpace(s)) {
				return true
			}
		}
	}
	return false
}

func isWebSocketRequest(r *http.Request) bool {
	return headerContains(r.Header, "Connection", "upgrade") &&
		headerContains(r.Header, "Upgrade", "websocket")
}

func (proxy *ProxyHttpServer) serveWebsocketTLS(ctx *ProxyCtx, w http.ResponseWriter, req *http.Request, tlsConfig *tls.Config, clientConn *tls.Conn) {
	targetURL := url.URL{Scheme: "https", Host: req.URL.Host, Path: req.URL.Path}
	log.Println(req.Header)

	proxyUrl, _ := url.Parse("http://1.2.3.4:8080")

	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetConn, err := proxyplease.NewDialContext(proxyplease.Proxy{
		URL:       proxyUrl,
		TLSConfig: tlsConfig,
		Headers:   &req.Header,
	})(cctx, "tcp", targetURL.String())
	log.Println("REMOTEADDR:", targetConn.RemoteAddr())
	if err != nil {
		ctx.Warnf("Error dialing target site: %v", err)
		return
	}
	defer targetConn.Close()

	log.Println("WSS: PERFORMING HANDSHAKE:", targetURL.String())
	// Perform handshake
	if err := proxy.websocketHandshake(ctx, req, targetConn, clientConn); err != nil {
		ctx.Warnf("Websocket handshake error: %v", err)
		return
	}

	log.Println("WSS: PROXYING CONNECTION:", targetURL.String())
	// Proxy wss connection
	proxy.proxyWebsocket(ctx, targetConn, clientConn)
}

func (proxy *ProxyHttpServer) serveWebsocket(ctx *ProxyCtx, w http.ResponseWriter, req *http.Request) {
	targetURL := url.URL{Scheme: "ws", Host: req.URL.Host, Path: req.URL.Path}

	proxyUrl, _ := url.Parse("http://1.2.3.4:8080")

	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targetConn, err := proxyplease.NewDialContext(proxyplease.Proxy{
		URL:     proxyUrl,
		Headers: &req.Header,
	})(cctx, "tcp", targetURL.String())
	if err != nil {
		ctx.Warnf("Error dialing target site: %v", err)
		return
	}
	defer targetConn.Close()

	// Connect to Client
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		ctx.Warnf("Hijack error: %v", err)
		return
	}

	// Perform handshake
	if err := proxy.websocketHandshake(ctx, req, targetConn, clientConn); err != nil {
		ctx.Warnf("Websocket handshake error: %v", err)
		return
	}

	// Proxy ws connection
	proxy.proxyWebsocket(ctx, targetConn, clientConn)
}

func (proxy *ProxyHttpServer) websocketHandshake(ctx *ProxyCtx, req *http.Request, targetSiteConn io.ReadWriter, clientConn io.ReadWriter) error {
	// write handshake request to target
	err := req.Write(targetSiteConn)
	if err != nil {
		ctx.Warnf("Error writing upgrade request: %v", err)
		return err
	}
	log.Println("Handshake Written")

	targetTLSReader := bufio.NewReader(targetSiteConn)

	// Read handshake response from target
	resp, err := http.ReadResponse(targetTLSReader, req)
	if err != nil {
		log.Println(resp)
		ctx.Warnf("Error reading handshake response  %v", err)
		return err
	}

	// Run response through handlers
	resp = proxy.filterResponse(resp, ctx)

	// Proxy handshake back to client
	err = resp.Write(clientConn)
	if err != nil {
		ctx.Warnf("Error writing handshake response: %v", err)
		return err
	}
	return nil
}

func (proxy *ProxyHttpServer) proxyWebsocket(ctx *ProxyCtx, dest io.ReadWriter, source io.ReadWriter) {
	errChan := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		ctx.Warnf("Websocket error: %v", err)
		errChan <- err
	}

	// Start proxying websocket data
	go cp(dest, source)
	go cp(source, dest)
	<-errChan
}

func dialWithConn(c *net.Conn, url url.URL, dialContext proxyplease.DialContext) (err error) {
	d := websocket.Dialer{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: 45 * time.Second,
		NetDial:          func(network, addr string) (net.Conn, error) { return *c, nil },
		NetDialContext:   dialContext,
	}

	_, _, err = d.Dial(url.String(), nil)

	return
}
