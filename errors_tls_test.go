package scrapemate_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gosom/scrapemate"
)

// leafWithDates returns a self-signed certificate valid from notBefore to notAfter.
func leafWithDates(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "maps.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"maps.test"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func TestTLSVerifyError_ErrorsIsAndUnwrap(t *testing.T) {
	inner := x509.UnknownAuthorityError{}
	err := &scrapemate.TLSVerifyError{Host: "maps.google.com", Class: scrapemate.TLSClassUnknownAuthority, Err: inner}

	require.ErrorIs(t, err, scrapemate.ErrTLSVerify)
	require.ErrorIs(t, err, inner)
	require.True(t, scrapemate.IsTLSVerifyError(err))
	require.Contains(t, err.Error(), "maps.google.com")
	require.Contains(t, err.Error(), scrapemate.TLSClassUnknownAuthority)

	// still recognised through wrapping
	wrapped := fmt.Errorf("fetch failed: %w", err)
	require.ErrorIs(t, wrapped, scrapemate.ErrTLSVerify)
	require.True(t, scrapemate.IsTLSVerifyError(wrapped))

	host, class, ok := scrapemate.TLSVerifyClass(wrapped)
	require.True(t, ok)
	require.Equal(t, "maps.google.com", host)
	require.Equal(t, scrapemate.TLSClassUnknownAuthority, class)
}

func TestTLSVerifyError_NilErrIsSafe(t *testing.T) {
	err := &scrapemate.TLSVerifyError{Host: "h", Class: scrapemate.TLSClassOther}
	require.NotEmpty(t, err.Error())
	require.NoError(t, errors.Unwrap(err))
}

func TestX509VerifyClass(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	valid := leafWithDates(t, now.Add(-time.Hour), now.Add(time.Hour))
	expired := leafWithDates(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	future := leafWithDates(t, now.Add(time.Hour), now.Add(48*time.Hour))

	tests := []struct {
		name string
		err  error
		cert *x509.Certificate
		want string
	}{
		{"unknown authority", x509.UnknownAuthorityError{}, valid, scrapemate.TLSClassUnknownAuthority},
		{"hostname mismatch", x509.HostnameError{Certificate: valid, Host: "other.test"}, valid, scrapemate.TLSClassHostnameMismatch},
		{"expired", x509.CertificateInvalidError{Cert: expired, Reason: x509.Expired}, expired, scrapemate.TLSClassExpired},
		{"not yet valid", x509.CertificateInvalidError{Cert: future, Reason: x509.Expired}, future, scrapemate.TLSClassNotYetValid},
		{"incompatible usage", x509.CertificateInvalidError{Cert: valid, Reason: x509.IncompatibleUsage}, valid, scrapemate.TLSClassOther},
		{"too many intermediates", x509.CertificateInvalidError{Cert: valid, Reason: x509.TooManyIntermediates}, valid, scrapemate.TLSClassOther},
		{"some other error", errors.New("boom"), valid, scrapemate.TLSClassOther},
		{"wrapped hostname error", fmt.Errorf("verify: %w", x509.HostnameError{Certificate: valid, Host: "h"}), valid, scrapemate.TLSClassHostnameMismatch},
		{"nil cert with date error", x509.CertificateInvalidError{Reason: x509.Expired}, nil, scrapemate.TLSClassExpired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, scrapemate.X509VerifyClass(tc.err, tc.cert, now))
		})
	}
}

func TestTLSVerifyClass_Chromium(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantHost  string
		wantClass string
		wantOK    bool
	}{
		{"authority", errors.New("page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://www.google.com/maps/search/x"), "www.google.com", scrapemate.TLSClassUnknownAuthority, true},
		{"common name", errors.New("net::ERR_CERT_COMMON_NAME_INVALID at https://maps.test:8443/"), "maps.test", scrapemate.TLSClassHostnameMismatch, true},
		{"date", fmt.Errorf("wrapped: %w", errors.New("page.goto: net::ERR_CERT_DATE_INVALID at https://a.b/")), "a.b", scrapemate.TLSClassDateInvalid, true},
		{"revoked", errors.New("net::ERR_CERT_REVOKED"), "", scrapemate.TLSClassOther, true},
		{"contains errors", errors.New("net::ERR_CERT_CONTAINS_ERRORS at https://x.y/"), "x.y", scrapemate.TLSClassOther, true},
		{"ssl protocol error is not verification", errors.New("net::ERR_SSL_PROTOCOL_ERROR at https://x.y/"), "", "", false},
		{"connection reset", errors.New("read tcp: connection reset by peer"), "", "", false},
		{"deadline", errors.New("context deadline exceeded"), "", "", false},
		{"407", errors.New("407 Proxy Authentication Required"), "", "", false},
		{"cert transparency is not matched", errors.New("net::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED"), "", "", false},
		{"nil", nil, "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, class, ok := scrapemate.TLSVerifyClass(tc.err)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantClass, class)
			require.Equal(t, tc.wantHost, host)
			require.Equal(t, tc.wantOK, scrapemate.IsTLSVerifyError(tc.err))
		})
	}
}

func TestTLSVerifyClass_IsNotMatchedByAnArbitraryError(t *testing.T) {
	require.False(t, scrapemate.IsTLSVerifyError(errors.New("x509: certificate signed by unknown authority")),
		"only the typed error and Chromium net errors count; a bare string is not a verdict")
}
