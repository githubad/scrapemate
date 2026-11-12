# GMX patches

This is the `gmx` branch of `github.com/githubad/scrapemate`, a fork of
[`gosom/scrapemate`](https://github.com/gosom/scrapemate) used by the GMX Google Maps
lead extractor (engine fork `githubad/google-maps-scraper`, branch `gmx`). It exists for
one reason: the engine must verify Google's TLS certificate, and both fetchers in
upstream switch verification off whenever a proxy is used.

- **Base:** `gosom/scrapemate` v1.4.1 (`1d7c7bf`, "Updates golang version to 1.27.3").
- **First tag of this fork:** `v1.4.1-gmx.1` (created and pushed by the owner).
- **Consumed by the engine with:** `replace github.com/gosom/scrapemate => github.com/githubad/scrapemate v1.4.1-gmx.1`.
- **Why a fork and not an upstream change:** upstream offers no setting for this. The patches
  are small, additive and **default off**, so they could be offered upstream as a setting.

## The rule: default behaviour is upstream's

Every patch sits behind the option `VerifyTLS` (`scrapemateapp.WithVerifyTLS(true)`,
`stealth.WithVerifyTLS(roots)`, `jshttp.JSFetcherOptions.VerifyTLS`). With the option off
(the default) the code path, the session configuration and the Chromium launch arguments
are exactly upstream's; tests assert this. The engine turns the option on for runs with
`-input-format jsonl` only.

## Patches (one commit each)

| ID | Commit | What | Files | Guarded by |
|---|---|---|---|---|
| P3 | `feat(errors): TLSVerifyError and TLSVerifyClass` | Typed error for a certificate that does not verify, classes (`unknown_authority`, `hostname_mismatch`, `expired`, `not_yet_valid`, `date_invalid`, `other`), `X509VerifyClass`, and `TLSVerifyClass`, which also recognises Chromium `net::ERR_CERT_*` navigation errors. `ERR_SSL_*` and other handshake failures are not matched. | `errors_tls.go` | `errors_tls_test.go` |
| P1 | `feat(stealth): verify the server certificate through the proxy (option)` | List-mode fetcher: verifies every connection against the system roots (or injected roots), the requested host name and the dates, inside the handshake azuretls already does through the proxy. | `adapters/fetchers/stealth/stealth.go`, `.../verify.go`, `scrapemateapp/config.go`, `scrapemateapp/scrapemateapp.go`, `go.mod` | `adapters/fetchers/stealth/verify_test.go`, `scrapemateapp/config_verify_test.go` |
| P2 | `feat(jshttp): keep Chromium certificate checks when VerifyTLS is set` | Browser-mode fetcher: leaves out `--ignore-certificate-errors` and `--ignore-certificate-errors-spki-list`. `--disable-web-security` is not a certificate switch and stays. | `adapters/fetchers/jshttp/jshttp.go`, `.../page_slot_pool.go`, `.../session_slot.go`, `scrapemateapp/jsfetcher_playwright.go` | `adapters/fetchers/jshttp/args_internal_test.go` |

(P1 stealth, P2 jshttp, P3 error typing are the names in the engine's spec; P3 is committed
first because P1 uses its type.)

## How P1 verifies without a direct dial (read this before touching it)

azuretls (v1.12.12) decides in `upgradeTLS` (`connection.go`):

- session flag `InsecureSkipVerify` **set**: builds `tls.Config{ServerName, InsecureSkipVerify: true}` and never touches the pin manager;
- flag **not set**: first calls `PinManager.AddHost`, which opens its **own direct TCP connection** to the host (`pinner.go`), outside the proxy, to learn the pins. That would contact Google from the owner's home IP.

So the flag stays **set**, as the pin bypass, and the real verification is a
`VerifyConnection` callback installed through the session's public `ModifyConfig` hook.
utls (v1.3.21) runs `VerifyConnection` for every connection, including resumptions,
regardless of `InsecureSkipVerify`. The browser ClientHello (the fingerprint) is applied
by azuretls after the config and independently of these fields; a test compares the
ClientHello extension order with and without the option.

The callback checks the leaf against the roots with `x509.Certificate.Verify` (intermediates
from the rest of the chain, `DNSName` = the server name, server-auth key usage, current
time). The system pool is loaded once per process. azuretls turns handshake errors into
plain strings, so the callback records its verdict per fetch and `Fetch` returns it as a
`*scrapemate.TLSVerifyError` (status 0, empty body).

If an azuretls or utls bump changes what `InsecureSkipVerify`, `ModifyConfig` or
`VerifyConnection` mean, the tests in `stealth/verify_test.go` fail (an untrusted
certificate must give a `TLSVerifyError`). Known limit: utls skips the callbacks when
Encrypted Client Hello is rejected; nothing in this stack configures ECH keys, so no ECH is offered.

## Browser mode

Chromium on Linux does not read `/etc/ssl/certs`: it uses its built-in root store (public
roots, which cover Google) plus the NSS database. A locally generated CA is not trusted
there without NSS. The engine documents this and tests only the untrusted case.

## go.mod

`github.com/Noooste/utls v1.3.21` moves from an indirect to a direct requirement (P1 imports
it for the `tls.Config` type of `ModifyConfig`). Same version, no new module.

## Tests

Run in the engine-dev container (Linux): `SCRAPEMATE_DIR=<this clone> bash scripts/engine.sh scrapemate test`
from the GMX repository. The stealth tests use a local TLS stub and a local CONNECT proxy
that dials the stub from `127.0.0.2`, so the stub can tell the proxy's connections from a
direct one (which would come from `127.0.0.1`); that needs the whole `127.0.0.0/8` loopback
(Linux). `TestMutation_LibraryPinPathDialsDirectly` shows the check works: it builds the
session the way the library does with verification on (flag off, no callback) and the stub
then sees a direct connection. `TestReport_VerifyHandshakeCost` prints the median fetch time
with and without verification (report-only, no gate).

`gofmt` note: a Windows clone with `core.autocrlf=true` has CRLF in the working tree, which
plain `gofmt -l` reports for every file; the GMX script formats LF-normalised content.

## Rebasing on upstream

Follow the GMX fork policy (ADR-0004): rebase `gmx` onto `upstream/main`, our patches adapt
to upstream, never the reverse. The patches touch `errors_tls.go` and `verify.go` (new
files), the stealth fetcher (struct, `New`, two small blocks in `Fetch`), one block of
Chromium arguments plus plumbing of one boolean through four structs in `jshttp`, and the
option in `scrapemateapp`. After any rebase or any azuretls/utls bump: run
`scrapemate test` and `vet`, then the engine's TLS end-to-end tests, then retag
(`v1.4.1-gmx.N` or the new base version).
