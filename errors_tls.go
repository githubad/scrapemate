package scrapemate

import (
	"crypto/x509"
	"errors"
	"net/url"
	"regexp"
	"time"
)

// Classes of a TLS certificate verification failure. They are stable strings:
// callers write them into logs and notes, so do not rename them.
const (
	// TLSClassUnknownAuthority: the chain does not lead to a trusted root.
	TLSClassUnknownAuthority = "unknown_authority"
	// TLSClassHostnameMismatch: the certificate is not valid for the requested host.
	TLSClassHostnameMismatch = "hostname_mismatch"
	// TLSClassExpired: the certificate's validity ended before now.
	TLSClassExpired = "expired"
	// TLSClassNotYetValid: the certificate's validity starts after now.
	TLSClassNotYetValid = "not_yet_valid"
	// TLSClassDateInvalid: expired or not yet valid, when the source (Chromium) does not say which.
	TLSClassDateInvalid = "date_invalid"
	// TLSClassOther: any other certificate verification failure.
	TLSClassOther = "other"
)

// ErrTLSVerify is the sentinel for a certificate verification failure; use
// errors.Is(err, ErrTLSVerify) or IsTLSVerifyError.
var ErrTLSVerify = errors.New("tls certificate verification failed")

// TLSVerifyError reports that the server's certificate did not verify for Host.
// It is not used for other handshake failures (reset, timeout, protocol error).
type TLSVerifyError struct {
	// Host is the URL host the certificate was checked for (no port).
	Host string
	// Class is one of the TLSClass* values.
	Class string
	// Err is the underlying x509 error, when there is one.
	Err error
}

// Error implements error.
func (e *TLSVerifyError) Error() string {
	msg := "tls verification failed for " + e.Host + ": " + e.Class
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}

	return msg
}

// Is makes errors.Is(err, ErrTLSVerify) true.
func (e *TLSVerifyError) Is(target error) bool {
	return target == ErrTLSVerify
}

// Unwrap returns the underlying error.
func (e *TLSVerifyError) Unwrap() error {
	return e.Err
}

// chromiumCertError matches the certificate errors Chromium reports for a
// navigation, for example "page.goto: net::ERR_CERT_AUTHORITY_INVALID at
// https://www.google.com/...". ERR_SSL_* (protocol) errors do not match.
var chromiumCertError = regexp.MustCompile(`net::ERR_CERT_[A-Z0-9_]+`)

var urlInMessage = regexp.MustCompile(`https?://[^\s]+`)

// IsTLSVerifyError reports whether err is a certificate verification failure:
// a *TLSVerifyError (also wrapped) or a Chromium net::ERR_CERT_* error.
func IsTLSVerifyError(err error) bool {
	_, _, ok := TLSVerifyClass(err)

	return ok
}

// TLSVerifyClass returns the host and class of a certificate verification
// failure, and false when err is not one. The host is empty when it cannot be
// told (a Chromium message without a URL).
func TLSVerifyClass(err error) (host, class string, ok bool) {
	if err == nil {
		return "", "", false
	}

	var tv *TLSVerifyError
	if errors.As(err, &tv) {
		return tv.Host, tv.Class, true
	}

	msg := err.Error()

	code := chromiumCertError.FindString(msg)
	if code == "" {
		return "", "", false
	}

	if raw := urlInMessage.FindString(msg); raw != "" {
		if u, perr := url.Parse(raw); perr == nil {
			host = u.Hostname()
		}
	}

	switch code {
	case "net::ERR_CERT_AUTHORITY_INVALID":
		class = TLSClassUnknownAuthority
	case "net::ERR_CERT_COMMON_NAME_INVALID":
		class = TLSClassHostnameMismatch
	case "net::ERR_CERT_DATE_INVALID":
		class = TLSClassDateInvalid
	default:
		class = TLSClassOther
	}

	return host, class, true
}

// X509VerifyClass maps an error from x509.Certificate.Verify to a class. cert is
// the leaf that was checked (used to tell expired from not yet valid); now is the
// time of the check.
func X509VerifyClass(err error, cert *x509.Certificate, now time.Time) string {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return TLSClassUnknownAuthority
	}

	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return TLSClassHostnameMismatch
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		if invalid.Reason != x509.Expired {
			return TLSClassOther
		}

		leaf := cert
		if leaf == nil {
			leaf = invalid.Cert
		}

		if leaf != nil && now.Before(leaf.NotBefore) {
			return TLSClassNotYetValid
		}

		return TLSClassExpired
	}

	return TLSClassOther
}
