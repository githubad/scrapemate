package stealth

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gosom/scrapemate"
)

// ---------------------------------------------------------------- certificates

// testPKI is a throw-away certificate authority generated at test time.
type testPKI struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T, name string) *testPKI {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testPKI{cert: cert, key: key, pool: pool}
}

// issue returns a leaf valid for names between notBefore and notAfter.
func (p *testPKI) issue(t *testing.T, names []string, notBefore, notAfter time.Time) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	require.NoError(t, err)

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// valid issues a leaf valid now for names.
func (p *testPKI) valid(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()

	return p.issue(t, names, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// ------------------------------------------------------------------- the stub

// stub is a local HTTPS server standing in for Google. It records the source
// address of every connection it accepts and the extension types of every
// ClientHello it receives.
type stub struct {
	t        *testing.T
	ln       net.Listener
	port     int
	chooser  func(connIndex int, sni string) *tls.Certificate
	mu       sync.Mutex
	remotes  []string
	hellos   map[int][]uint16
	nextConn int
}

func newStub(t *testing.T, chooser func(connIndex int, sni string) *tls.Certificate) *stub {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &stub{t: t, chooser: chooser, hellos: map[int][]uint16{}}
	s.ln = &recordingListener{Listener: ln, s: s}
	s.port = ln.Addr().(*net.TCPAddr).Port

	cfg := &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			idx := -1
			if rc, ok := h.Conn.(*recConn); ok {
				idx = rc.index
			}

			cert := s.chooser(idx, h.ServerName)

			return &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}, nil
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://consent.test:%d/ok", s.port), http.StatusFound)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = srv.Serve(tls.NewListener(s.ln, cfg)) }()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = s.ln.Close()
	})

	return s
}

func (s *stub) addr() string { return fmt.Sprintf("127.0.0.1:%d", s.port) }

// remoteIPs returns the source IP of every accepted connection, in order.
func (s *stub) remoteIPs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.remotes...)
}

// helloExtensions returns the ClientHello extension types per connection index.
func (s *stub) helloExtensions() map[int][]uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[int][]uint16, len(s.hellos))
	for k, v := range s.hellos {
		out[k] = append([]uint16(nil), v...)
	}

	return out
}

type recordingListener struct {
	net.Listener
	s *stub
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())

	l.s.mu.Lock()
	idx := l.s.nextConn
	l.s.nextConn++
	l.s.remotes = append(l.s.remotes, host)
	l.s.mu.Unlock()

	return &recConn{Conn: c, s: l.s, index: idx}, nil
}

// recConn captures the first TLS record (the ClientHello) a client sends.
type recConn struct {
	net.Conn
	s     *stub
	index int
	buf   []byte
	done  bool
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.done {
		c.buf = append(c.buf, b[:n]...)
		c.tryParse()
	}

	return n, err
}

func (c *recConn) tryParse() {
	if len(c.buf) < 5 || c.buf[0] != 0x16 {
		return
	}

	recLen := int(c.buf[3])<<8 | int(c.buf[4])
	if len(c.buf) < 5+recLen {
		return
	}

	c.done = true

	types := clientHelloExtensionTypes(c.buf[5 : 5+recLen])

	c.s.mu.Lock()
	c.s.hellos[c.index] = types
	c.s.mu.Unlock()
}

// clientHelloExtensionTypes lists the extension types of a ClientHello
// handshake message in the order they were sent (nil if it cannot be parsed).
func clientHelloExtensionTypes(hs []byte) []uint16 {
	// handshake header: type(1)=1, length(3); body: version(2), random(32), ...
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil
	}

	p := 4 + 2 + 32
	if len(hs) < p+1 {
		return nil
	}

	p += 1 + int(hs[p]) // session id

	if len(hs) < p+2 {
		return nil
	}

	p += 2 + (int(hs[p])<<8 | int(hs[p+1])) // cipher suites

	if len(hs) < p+1 {
		return nil
	}

	p += 1 + int(hs[p]) // compression methods

	if len(hs) < p+2 {
		return nil
	}

	extLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2

	end := p + extLen
	if end > len(hs) {
		return nil
	}

	var types []uint16

	for p+4 <= end {
		typ := uint16(hs[p])<<8 | uint16(hs[p+1])
		l := int(hs[p+2])<<8 | int(hs[p+3])
		types = append(types, typ)
		p += 4 + l
	}

	return types
}

// ------------------------------------------------------------------ the proxy

// connectProxy is a local HTTP CONNECT proxy. It maps the test host names to the
// stub and dials it from 127.0.0.2, so the stub can tell the proxy's connections
// from any direct connection (which would come from 127.0.0.1).
type connectProxy struct {
	ln       net.Listener
	hosts    map[string]string // host name -> stub address
	mu       sync.Mutex
	connects []string
	clients  []string
	refuse   int // when non-zero, answer every CONNECT with this status
}

const proxySourceIP = "127.0.0.2"

func newConnectProxy(t *testing.T, hosts map[string]string) *connectProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	p := &connectProxy{ln: ln, hosts: hosts}

	go p.serve()

	t.Cleanup(func() { _ = ln.Close() })

	return p
}

func (p *connectProxy) url() string { return "http://" + p.ln.Addr().String() }

func (p *connectProxy) connectTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.connects...)
}

func (p *connectProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}

		go p.handle(c)
	}
}

func (p *connectProxy) handle(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")

		return
	}

	client, _, _ := net.SplitHostPort(c.RemoteAddr().String())

	p.mu.Lock()
	p.connects = append(p.connects, req.Host)
	p.clients = append(p.clients, client)
	refuse := p.refuse
	p.mu.Unlock()

	if refuse != 0 {
		_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n\r\n", refuse, http.StatusText(refuse))

		return
	}

	name := req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		name = h
	}

	target, ok := p.hosts[strings.ToLower(name)]
	if !ok {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")

		return
	}

	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(proxySourceIP)}, Timeout: 5 * time.Second}

	up, err := d.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")

		return
	}
	defer up.Close()

	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")

	done := make(chan struct{}, 2)

	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()

	<-done
}

// ------------------------------------------------------------ fetch + asserts

// fixedProxy is a proxy rotator with one proxy.
type fixedProxy struct{ url string }

func (f fixedProxy) Next() scrapemate.Proxy { return scrapemate.Proxy{URL: f.url} }

func fetch(t *testing.T, f scrapemate.HTTPFetcher, rawURL string) scrapemate.Response {
	t.Helper()

	job := &scrapemate.Job{Method: http.MethodGet, URL: rawURL, Timeout: 15 * time.Second}

	return f.Fetch(t.Context(), job)
}

// directDials returns the source IPs of connections to the stub that did not come
// from the proxy. A non-empty result means something dialled the stub directly.
func directDials(remotes []string) []string {
	var direct []string

	for _, r := range remotes {
		if r != proxySourceIP {
			direct = append(direct, r)
		}
	}

	return direct
}

// assertNoDirectDial fails the test when the stub saw a connection that did not
// come from the proxy.
func assertNoDirectDial(t *testing.T, s *stub) {
	t.Helper()

	require.Empty(t, directDials(s.remoteIPs()), "the stub saw a connection that did not come from the proxy")
}
