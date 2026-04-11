package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// ================================================
// TLS Proxy - Go uTLS reverse proxy
//
// 支持两种模式:
//   1. X-Target-Host: 仅主机名，路径从请求 URL 获取
//   2. X-Target-Url:  完整 URL（优先级更高）
//
// 使用 Chrome 最新指纹，ALPN 协商 h2/http1.1
// ================================================

const (
	defaultPort  = 8081
	headerTarget = "X-Target-Url"
	headerHost   = "X-Target-Host"
	headerProxy  = "X-Proxy-Url"
)

// 全局 RoundTripper 缓存（按 proxyURL 分组，复用 H2 连接）
var (
	rtCacheMu sync.Mutex
	rtCache   = make(map[string]*utlsRoundTripper)
)

func getOrCreateRT(proxyURL string) *utlsRoundTripper {
	rtCacheMu.Lock()
	defer rtCacheMu.Unlock()
	if rt, ok := rtCache[proxyURL]; ok {
		return rt
	}
	rt := newUTLSRoundTripper(proxyURL)
	rtCache[proxyURL] = rt
	return rt
}

// ================ uTLS RoundTripper ================
// 根据 ALPN 协商结果自动选择 H2 或 H1 传输

type utlsRoundTripper struct {
	proxyURL string
	mu       sync.Mutex
	h2Conns  map[string]*http2.ClientConn // H2 连接缓存 (per host)
}

func newUTLSRoundTripper(proxyURL string) *utlsRoundTripper {
	return &utlsRoundTripper{
		proxyURL: proxyURL,
		h2Conns:  make(map[string]*http2.ClientConn),
	}
}

func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		if req.URL.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	// 尝试复用已有的 H2 连接
	rt.mu.Lock()
	if cc, ok := rt.h2Conns[addr]; ok {
		rt.mu.Unlock()
		if cc.CanTakeNewRequest() {
			resp, err := cc.RoundTrip(req)
			if err == nil {
				return resp, nil
			}
			log.Printf("[TLS-PROXY] Cached H2 conn failed for %s: %v, reconnecting", addr, err)
		}
		rt.mu.Lock()
		delete(rt.h2Conns, addr)
		rt.mu.Unlock()
	} else {
		rt.mu.Unlock()
	}

	// 建立新的 uTLS 连接
	conn, err := dialUTLS(req.Context(), "tcp", addr, rt.proxyURL)
	if err != nil {
		return nil, err
	}

	// 根据 ALPN 协商结果决定走 H2 还是 H1
	alpn := conn.ConnectionState().NegotiatedProtocol
	log.Printf("[TLS-PROXY] Connected to %s, ALPN: %q", addr, alpn)

	if alpn == "h2" {
		// HTTP/2: 创建 H2 ClientConn
		t2 := &http2.Transport{
			StrictMaxConcurrentStreams: true,
			AllowHTTP:                  false,
		}
		cc, err := t2.NewClientConn(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("h2 client conn: %w", err)
		}

		rt.mu.Lock()
		rt.h2Conns[addr] = cc
		rt.mu.Unlock()

		return cc.RoundTrip(req)
	}

	// HTTP/1.1: 通过一次性 Transport 使用已建立的 TLS 连接
	used := false
	t1 := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if !used {
				used = true
				return conn, nil
			}
			return dialUTLS(ctx, network, a, rt.proxyURL)
		},
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
	}

	resp, err := t1.RoundTrip(req)
	if err != nil {
		conn.Close()
	}
	return resp, err
}

// ================ uTLS Dial ================

func dialUTLS(ctx context.Context, network, addr string, proxyURL string) (*utls.UConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// TCP 连接（可能经过代理）
	var rawConn net.Conn
	if proxyURL != "" {
		rawConn, err = dialViaProxy(ctx, network, addr, proxyURL)
	} else {
		var d net.Dialer
		rawConn, err = d.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// uTLS 握手 - 使用 Chrome 最新自动指纹
	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_Auto)

	// 握手超时
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	} else {
		tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	// 握手完成，清除超时
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// ================ Proxy Dialer ================

func dialViaProxy(ctx context.Context, network, addr string, proxyURL string) (net.Conn, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %w", err)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "socks5", "socks5h", "socks4", "socks":
		var auth *proxy.Auth
		if parsed.User != nil {
			auth = &proxy.Auth{
				User: parsed.User.Username(),
			}
			auth.Password, _ = parsed.User.Password()
		}
		dialer, err := proxy.SOCKS5("tcp", parsed.Host, auth, &net.Dialer{
			Timeout: 15 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
			return ctxDialer.DialContext(ctx, network, addr)
		}
		return dialer.Dial(network, addr)

	case "http", "https":
		proxyConn, err := net.DialTimeout("tcp", parsed.Host, 15*time.Second)
		if err != nil {
			return nil, fmt.Errorf("connect to http proxy: %w", err)
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if parsed.User != nil {
			username := parsed.User.Username()
			password, _ := parsed.User.Password()
			cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", cred)
		}
		connectReq += "\r\n"

		if _, err = proxyConn.Write([]byte(connectReq)); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy CONNECT write: %w", err)
		}

		buf := make([]byte, 4096)
		n, err := proxyConn.Read(buf)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy CONNECT read: %w", err)
		}
		if !strings.Contains(string(buf[:n]), "200") {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy CONNECT rejected: %s", strings.TrimSpace(string(buf[:n])))
		}

		return proxyConn, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", parsed.Scheme)
	}
}

// ================ HTTP Handler ================

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 优先使用 X-Target-Url，其次使用 X-Target-Host
	targetURL := r.Header.Get(headerTarget)
	proxyURL := r.Header.Get(headerProxy)

	if targetURL == "" {
		// 兼容旧模式: X-Target-Host
		targetHost := r.Header.Get(headerHost)
		if targetHost == "" {
			targetHost = "q.us-east-1.amazonaws.com"
		}
		targetURL = "https://" + targetHost + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid target url: %s"}`, err), http.StatusBadRequest)
		return
	}

	log.Printf("[TLS-PROXY] %s %s -> %s", r.Method, r.URL.Path, parsed.Host)

	// Create upstream request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to create request: %s"}`, err), http.StatusInternalServerError)
		return
	}

	// Copy headers (skip internal + hop-by-hop)
	// 彻底清理所有非浏览器标头，严格保持小写
	for key, vals := range r.Header {
		lk := strings.ToLower(key)
		if lk == strings.ToLower(headerTarget) || lk == strings.ToLower(headerHost) || lk == strings.ToLower(headerProxy) {
			continue
		}
		// 移除所有代理、本地网络特征标头，防止 Cloudflare 识别
		if lk == "connection" || lk == "keep-alive" || lk == "transfer-encoding" ||
			lk == "te" || lk == "trailer" || lk == "upgrade" || lk == "host" ||
			lk == "x-forwarded-for" || lk == "x-real-ip" || lk == "x-forwarded-proto" ||
			lk == "x-forwarded-host" || lk == "via" || lk == "proxy-connection" ||
			lk == "cf-connecting-ip" || lk == "true-client-ip" {
			continue
		}
		outReq.Header[key] = vals
	}
	outReq.Host = parsed.Host

	// 强制设置标准的 Accept-Encoding
	if ae := outReq.Header["Accept-Encoding"]; len(ae) > 0 {
		outReq.Header["Accept-Encoding"] = []string{"gzip, deflate, br, zstd"}
	}

	// Execute via uTLS RoundTripper
	rt := getOrCreateRT(proxyURL)
	resp, err := rt.RoundTrip(outReq)
	if err != nil {
		log.Printf("[TLS-PROXY] RoundTrip error -> %s: %v", parsed.Host, err)
		http.Error(w, fmt.Sprintf(`{"error":"upstream request failed: %s"}`, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream body (SSE-friendly: flush after every read)
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				log.Printf("[TLS-PROXY] Write error: %v", writeErr)
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				log.Printf("[TLS-PROXY] Read error: %v", readErr)
			}
			return
		}
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	port := flag.Int("port", defaultPort, "Listen port")
	upstreamProxy := flag.String("proxy", "", "Upstream proxy URL (optional)")
	flag.Parse()

	// 预创建默认 RoundTripper
	getOrCreateRT(*upstreamProxy)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", proxyHandler)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("[TLS-PROXY] Listening on %s (Chrome fingerprint, H2 enabled)", addr)
	if *upstreamProxy != "" {
		log.Printf("[TLS-PROXY] Using upstream proxy: %s", *upstreamProxy)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE 流式响应不设写超时
		IdleTimeout:  120 * time.Second,
	}

	// 优雅关闭
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("[TLS-PROXY] Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[TLS-PROXY] Server error: %v", err)
	}
}
