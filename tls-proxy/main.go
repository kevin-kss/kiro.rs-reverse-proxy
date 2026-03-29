package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// nodejsSpec returns a uTLS ClientHelloSpec that exactly reproduces the
// TLS fingerprint of Electron 39.6.0 (Kiro IDE).
//
// JA3 hash:  71dc8c533dd919ae9f4963224a4ba8fd
// JA4:       t13d1810_5d04281c6031_78e6aca7449b
func nodejsSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.3 (BoringSSL order)
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS 1.2
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{
				Renegotiation: utls.RenegotiateOnceAsClient,
			},
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
				},
			},
			&utls.SupportedPointsExtension{
				SupportedPoints: []byte{0},
			},
			&utls.SessionTicketExtension{},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
				},
			},
			&utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{{Group: utls.X25519}},
			},
			&utls.PSKKeyExchangeModesExtension{
				Modes: []uint8{1},
			},
			&utls.SupportedVersionsExtension{
				Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12},
			},
		},
	}
}

func nodejsDialTLS(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

	var rawConn net.Conn
	var err error

	if proxyURL != nil {
		rawConn, err = dialer.DialContext(ctx, "tcp", proxyURL.Host)
		if err != nil {
			return nil, fmt.Errorf("dial proxy: %w", err)
		}

		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if proxyURL.User != nil {
			cred := proxyURL.User.String()
			connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
		}
		if err := connectReq.Write(rawConn); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("write CONNECT: %w", err)
		}

		br := bufio.NewReader(rawConn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		if resp.StatusCode != 200 {
			rawConn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %d %s", resp.StatusCode, resp.Status)
		}
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dial direct: %w", err)
		}
	}

	host, _, _ := net.SplitHostPort(addr)
	uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := uConn.ApplyPreset(nodejsSpec()); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apply nodejs spec: %w", err)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return uConn, nil
}

func createNodejsTransport(proxyURL string) *http.Transport {
	var parsedProxy *url.URL
	if proxyURL != "" {
		parsedProxy, _ = url.Parse(proxyURL)
	}

	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nodejsDialTLS(ctx, parsedProxy, addr)
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if parsedProxy != nil {
				return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, parsedProxy.Host)
			}
			return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // No timeout for streaming
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
	}
}

var (
	httpClient     *http.Client
	httpClientOnce sync.Once
	upstreamProxy  string
)

func getHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		httpClient = &http.Client{
			Timeout:   0, // No timeout for streaming
			Transport: createNodejsTransport(upstreamProxy),
		}
	})
	return httpClient
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Build upstream URL
	targetHost := r.Header.Get("X-Target-Host")
	if targetHost == "" {
		targetHost = "q.us-east-1.amazonaws.com"
	}
	targetURL := "https://" + targetHost + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Create upstream request
	ctx := r.Context()
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("create request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers (except hop-by-hop)
	hopHeaders := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
		"X-Target-Host":       true,
	}
	for k, vv := range r.Header {
		if hopHeaders[k] {
			continue
		}
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}

	// Override Host header
	upstreamReq.Host = targetHost

	// Send request
	client := getHTTPClient()
	resp, err := client.Do(upstreamReq)
	if err != nil {
		log.Printf("upstream request failed: %v", err)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body with immediate flush for SSE
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 1) // Read byte by byte for real-time streaming
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			// Flush on newline (SSE events end with \n\n)
			if canFlush && buf[0] == '\n' {
				flusher.Flush()
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("read upstream body: %v", err)
			}
			break
		}
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	port := flag.Int("port", 8081, "Listen port")
	proxy := flag.String("proxy", "", "Upstream proxy URL (optional)")
	flag.Parse()

	upstreamProxy = *proxy

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", proxyHandler)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("TLS proxy listening on %s (Electron fingerprint)", addr)
	if upstreamProxy != "" {
		log.Printf("Using upstream proxy: %s", upstreamProxy)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
