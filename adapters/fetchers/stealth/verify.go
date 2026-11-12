package stealth

import (
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/Noooste/azuretls-client"
	tls "github.com/Noooste/utls"

	"github.com/gosom/scrapemate"
)

// Option configures the stealth fetcher.
type Option func(*stealthFetch)

// WithVerifyTLS makes the fetcher verify the server certificate of every
// connection: the chain to roots (the system roots when roots is nil), the
// requested host name and the validity dates. A failure ends the fetch with a
// *scrapemate.TLSVerifyError in Response.Error, status 0, no body.
//
// The verification runs inside the TLS handshake of the connection that
// azuretls already opens (through the proxy). It does not use azuretls's pin
// manager, which dials the host directly, and it does not change the browser
// fingerprint. Without this option the fetcher behaves as upstream.
func WithVerifyTLS(roots *x509.CertPool) Option {
	return func(o *stealthFetch) {
		o.verify = true
		o.roots = roots
	}
}

var (
	systemRootsOnce sync.Once
	systemRoots     *x509.CertPool
	systemRootsErr  error
)

// systemCertPool loads the system roots once per process (SystemCertPool copies
// the pool on every call).
func systemCertPool() (*x509.CertPool, error) {
	systemRootsOnce.Do(func() {
		systemRoots, systemRootsErr = x509.SystemCertPool()
	})

	return systemRoots, systemRootsErr
}

// verifyVerdict keeps the first certificate failure of one fetch. azuretls turns
// handshake errors into plain strings, so the typed error is kept here.
type verifyVerdict struct {
	mu  sync.Mutex
	err *scrapemate.TLSVerifyError
}

func (v *verifyVerdict) set(e *scrapemate.TLSVerifyError) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.err == nil {
		v.err = e
	}
}

// failure returns the recorded failure; it is safe on a nil verdict.
func (v *verifyVerdict) failure() *scrapemate.TLSVerifyError {
	if v == nil {
		return nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	return v.err
}

// configureVerify installs the verifier on the session when WithVerifyTLS was
// given and returns the verdict to read after the request; it returns nil and
// leaves the session untouched otherwise.
//
// session.InsecureSkipVerify is set on purpose: in azuretls that flag is also the
// switch that skips its pin manager, whose AddHost opens a direct connection to
// the host (outside the proxy). The real verification is the VerifyConnection
// callback below, which utls runs for every connection.
func (o *stealthFetch) configureVerify(session *azuretls.Session) *verifyVerdict {
	if !o.verify {
		return nil
	}

	verdict := &verifyVerdict{}

	session.InsecureSkipVerify = true
	session.ModifyConfig = func(cfg *tls.Config) error {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			roots := o.roots
			if roots == nil {
				var err error

				roots, err = systemCertPool()
				if err != nil {
					te := &scrapemate.TLSVerifyError{Host: cs.ServerName, Class: scrapemate.TLSClassOther, Err: err}
					verdict.set(te)

					return te
				}
			}

			if te := verifyChain(cs.ServerName, cs.PeerCertificates, roots, time.Now()); te != nil {
				verdict.set(te)

				return te
			}

			return nil
		}

		return nil
	}

	return verdict
}

// verifyChain checks the presented chain for host against roots at now. It
// returns nil when the chain is good.
func verifyChain(host string, certs []*x509.Certificate, roots *x509.CertPool, now time.Time) *scrapemate.TLSVerifyError {
	if host == "" {
		return &scrapemate.TLSVerifyError{Class: scrapemate.TLSClassOther, Err: errors.New("no server name to verify the certificate for")}
	}

	if len(certs) == 0 {
		return &scrapemate.TLSVerifyError{Host: host, Class: scrapemate.TLSClassOther, Err: errors.New("the server presented no certificate")}
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return &scrapemate.TLSVerifyError{Host: host, Class: scrapemate.X509VerifyClass(err, certs[0], now), Err: err}
	}

	return nil
}
