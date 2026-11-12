package stealth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/Noooste/azuretls-client"
	"github.com/stretchr/testify/require"

	"github.com/gosom/scrapemate"
)

// rig is a stub, a proxy and the certificates for one test.
type rig struct {
	stub  *stub
	proxy *connectProxy
}

func newRig(t *testing.T, chooser func(connIndex int, sni string) *tls.Certificate) *rig {
	t.Helper()

	s := newStub(t, chooser)
	p := newConnectProxy(t, map[string]string{
		"maps.test":    s.addr(),
		"consent.test": s.addr(),
		"localhost":    s.addr(),
	})

	return &rig{stub: s, proxy: p}
}

func (r *rig) url(host, path string) string {
	return fmt.Sprintf("https://%s:%d%s", host, r.stub.port, path)
}

func (r *rig) fetcher(opts ...Option) scrapemate.HTTPFetcher {
	return New(azuretls.Firefox, fixedProxy{url: r.proxy.url()}, opts...)
}

func tlsError(t *testing.T, resp scrapemate.Response) *scrapemate.TLSVerifyError {
	t.Helper()

	require.Error(t, resp.Error)

	var tv *scrapemate.TLSVerifyError
	require.True(t, errors.As(resp.Error, &tv), "want a TLSVerifyError, got %T: %v", resp.Error, resp.Error)
	require.ErrorIs(t, resp.Error, scrapemate.ErrTLSVerify)
	require.Zero(t, resp.StatusCode)
	require.Empty(t, resp.Body)

	return tv
}

func TestVerify_TrustedCA_OK(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.valid(t, "maps.test", "consent.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	resp := fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/ok"))

	require.NoError(t, resp.Error)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hello", string(resp.Body))

	// every connection to the stub came from the proxy, to the requested name
	assertNoDirectDial(t, r.stub)
	require.NotEmpty(t, r.stub.remoteIPs())
	require.Equal(t, []string{fmt.Sprintf("maps.test:%d", r.stub.port)}, r.proxy.connectTargets())
}

func TestVerify_UntrustedCA(t *testing.T) {
	trusted := newPKI(t, "trusted")
	rogue := newPKI(t, "rogue")
	cert := rogue.valid(t, "maps.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	resp := fetch(t, r.fetcher(WithVerifyTLS(trusted.pool)), r.url("maps.test", "/ok"))

	tv := tlsError(t, resp)
	require.Equal(t, scrapemate.TLSClassUnknownAuthority, tv.Class)
	require.Equal(t, "maps.test", tv.Host)
	assertNoDirectDial(t, r.stub)
}

func TestVerify_WrongHost(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.valid(t, "other.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	tv := tlsError(t, fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/ok")))

	require.Equal(t, scrapemate.TLSClassHostnameMismatch, tv.Class)
	require.Equal(t, "maps.test", tv.Host)
}

func TestVerify_Expired(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.issue(t, []string{"maps.test"}, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	tv := tlsError(t, fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/ok")))

	require.Equal(t, scrapemate.TLSClassExpired, tv.Class)
}

func TestVerify_NotYetValid(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.issue(t, []string{"maps.test"}, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	tv := tlsError(t, fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/ok")))

	require.Equal(t, scrapemate.TLSClassNotYetValid, tv.Class)
}

// AS-20: a redirect to another host (a stand-in for consent.google.com).
func TestVerify_RedirectToGoodHost(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.valid(t, "maps.test", "consent.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	resp := fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/redir"))

	require.NoError(t, resp.Error)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hello", string(resp.Body))
	require.Equal(t, []string{
		fmt.Sprintf("maps.test:%d", r.stub.port),
		fmt.Sprintf("consent.test:%d", r.stub.port),
	}, r.proxy.connectTargets(), "the redirect target was reached through the proxy")
	assertNoDirectDial(t, r.stub)
}

// AS-20: a redirect to a host whose certificate does not verify.
func TestVerify_RedirectToBadHost(t *testing.T) {
	pki := newPKI(t, "trusted")
	rogue := newPKI(t, "rogue")
	good := pki.valid(t, "maps.test")
	rogueCert := rogue.valid(t, "consent.test")
	wrongName := pki.valid(t, "elsewhere.test")

	t.Run("untrusted authority", func(t *testing.T) {
		r := newRig(t, func(_ int, sni string) *tls.Certificate {
			if sni == "consent.test" {
				return rogueCert
			}

			return good
		})

		tv := tlsError(t, fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/redir")))

		require.Equal(t, scrapemate.TLSClassUnknownAuthority, tv.Class)
		require.Equal(t, "consent.test", tv.Host)
	})

	t.Run("certificate for another name", func(t *testing.T) {
		r := newRig(t, func(_ int, sni string) *tls.Certificate {
			if sni == "consent.test" {
				return wrongName
			}

			return good
		})

		tv := tlsError(t, fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/redir")))

		require.Equal(t, scrapemate.TLSClassHostnameMismatch, tv.Class)
		require.Equal(t, "consent.test", tv.Host)
	})
}

// Every connection is verified, not only the first one.
func TestVerify_EveryConnectionIsVerified(t *testing.T) {
	pki := newPKI(t, "trusted")
	rogue := newPKI(t, "rogue")
	good := pki.valid(t, "maps.test")
	bad := rogue.valid(t, "maps.test")
	r := newRig(t, func(idx int, _ string) *tls.Certificate {
		if idx == 0 {
			return good
		}

		return bad
	})

	f := r.fetcher(WithVerifyTLS(pki.pool))

	require.NoError(t, fetch(t, f, r.url("maps.test", "/ok")).Error)
	tv := tlsError(t, fetch(t, f, r.url("maps.test", "/ok")))
	require.Equal(t, scrapemate.TLSClassUnknownAuthority, tv.Class)
	assertNoDirectDial(t, r.stub)
}

// A verification failure is one handshake: the fetcher does not retry it itself.
func TestVerify_FailureIsOneConnection(t *testing.T) {
	pki := newPKI(t, "trusted")
	rogue := newPKI(t, "rogue")
	cert := rogue.valid(t, "maps.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	tlsError(t, fetch(t, r.fetcher(WithVerifyTLS(pki.pool)), r.url("maps.test", "/ok")))

	require.Len(t, r.stub.remoteIPs(), 1)
	require.Len(t, r.proxy.connectTargets(), 1)
}

// Default off: the fetcher behaves as upstream and accepts an untrusted certificate.
func TestVerify_DefaultOffAcceptsUntrustedCertificate(t *testing.T) {
	rogue := newPKI(t, "rogue")
	cert := rogue.valid(t, "maps.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	resp := fetch(t, r.fetcher(), r.url("maps.test", "/ok"))

	require.NoError(t, resp.Error)
	require.Equal(t, 200, resp.StatusCode)
	assertNoDirectDial(t, r.stub)
}

func TestConfigureVerify_OffLeavesTheSessionAsUpstream(t *testing.T) {
	f := New(azuretls.Firefox, fixedProxy{url: "http://127.0.0.1:1"}).(*stealthFetch)
	s := azuretls.NewSession()
	t.Cleanup(s.Close)

	require.Nil(t, f.configureVerify(s))
	require.Nil(t, s.ModifyConfig)
	require.False(t, s.InsecureSkipVerify, "upstream sets the flag in Fetch, not here")
}

func TestConfigureVerify_OnKeepsThePinBypassAndInstallsTheVerifier(t *testing.T) {
	f := New(azuretls.Firefox, nil, WithVerifyTLS(nil)).(*stealthFetch)
	s := azuretls.NewSession()
	t.Cleanup(s.Close)

	v := f.configureVerify(s)

	require.NotNil(t, v)
	require.NotNil(t, s.ModifyConfig)
	require.True(t, s.InsecureSkipVerify, "azuretls uses this flag to skip its pin manager (which dials directly)")
}

func TestVerifyChain(t *testing.T) {
	pki := newPKI(t, "trusted")
	leaf := mustLeaf(t, pki.valid(t, "maps.test"))
	now := time.Now()

	t.Run("ok", func(t *testing.T) {
		require.Nil(t, verifyChain("maps.test", []*x509.Certificate{leaf}, pki.pool, now))
	})

	t.Run("empty server name is class other", func(t *testing.T) {
		tv := verifyChain("", []*x509.Certificate{leaf}, pki.pool, now)
		require.NotNil(t, tv)
		require.Equal(t, scrapemate.TLSClassOther, tv.Class)
	})

	t.Run("no certificates is class other", func(t *testing.T) {
		tv := verifyChain("maps.test", nil, pki.pool, now)
		require.NotNil(t, tv)
		require.Equal(t, scrapemate.TLSClassOther, tv.Class)
	})

	t.Run("wrong usage is class other", func(t *testing.T) {
		// a CA certificate is not a server certificate for another host
		tv := verifyChain("maps.test", []*x509.Certificate{pki.cert}, pki.pool, now)
		require.NotNil(t, tv)
	})
}

func mustLeaf(t *testing.T, c *tls.Certificate) *x509.Certificate {
	t.Helper()

	cert, err := x509.ParseCertificate(c.Certificate[0])
	require.NoError(t, err)

	return cert
}

// The pin path of the library dials the host itself. This test proves the
// no-direct-dial check can see that: it builds a session the way upstream does
// when verification is switched on (flag off, no callback) and the stub then sees
// a connection that did not come from the proxy. Without this, a passing
// assertNoDirectDial elsewhere would prove nothing.
func TestMutation_LibraryPinPathDialsDirectly(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.valid(t, "localhost", "maps.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	s := azuretls.NewSession()
	t.Cleanup(s.Close)

	require.NoError(t, s.SetProxy(r.proxy.url()))
	s.Browser = azuretls.Firefox

	// the handshake itself is expected to fail (the CA is not in the system roots);
	// what matters is who connected to the stub
	_, _ = s.Do(&azuretls.Request{Method: "GET", Url: r.url("localhost", "/ok"), TimeOut: 5 * time.Second})

	direct := directDials(r.stub.remoteIPs())
	require.NotEmpty(t, direct, "the library's pin manager should have dialled the stub directly: %v", r.stub.remoteIPs())
	require.Contains(t, r.stub.remoteIPs(), proxySourceIP, "and the proxy connection exists too")
}

// The browser fingerprint must not change: the ClientHello extensions, in order,
// are the same with and without verification.
func TestVerify_ClientHelloIsUnchanged(t *testing.T) {
	pki := newPKI(t, "trusted")
	cert := pki.valid(t, "maps.test")

	hello := func(opts ...Option) []uint16 {
		r := newRig(t, func(int, string) *tls.Certificate { return cert })
		require.NoError(t, fetch(t, r.fetcher(opts...), r.url("maps.test", "/ok")).Error)

		ext := r.stub.helloExtensions()[0]
		require.NotEmpty(t, ext)

		return ext
	}

	off := hello()
	on := hello(WithVerifyTLS(pki.pool))

	require.True(t, slices.Equal(off, on), "extension order differs:\n off %v\n on  %v", off, on)
}

// Report-only (no gate): the median time a fetch takes with and without
// verification, over 50 connections each. A loopback handshake is cheap, so a
// percentage means little; the number is printed for the record (go test -v).
func TestReport_VerifyHandshakeCost(t *testing.T) {
	if testing.Short() {
		t.Skip("report-only measurement")
	}

	pki := newPKI(t, "trusted")
	cert := pki.valid(t, "maps.test")
	r := newRig(t, func(int, string) *tls.Certificate { return cert })

	const n = 50

	measure := func(f scrapemate.HTTPFetcher) time.Duration {
		d := make([]time.Duration, 0, n)

		for range n {
			start := time.Now()
			resp := fetch(t, f, r.url("maps.test", "/ok"))
			require.NoError(t, resp.Error)
			d = append(d, time.Since(start))
		}

		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })

		return d[n/2]
	}

	off := measure(r.fetcher())
	on := measure(r.fetcher(WithVerifyTLS(pki.pool)))

	t.Logf("REPORT median fetch over %d connections: verification off %v, on %v, added %v (report-only, no gate)",
		n, off, on, on-off)
}
