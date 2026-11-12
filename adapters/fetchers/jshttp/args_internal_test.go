package jshttp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// upstreamChromiumArgs is the argument list of scrapemate v1.4.1, copied here on
// purpose: with VerifyTLS off the launch arguments must stay exactly this.
var upstreamChromiumArgs = []string{
	`--start-maximized`,
	`--no-default-browser-check`,
	`--disable-dev-shm-usage`,
	`--no-sandbox`,
	`--disable-setuid-sandbox`,
	`--no-zygote`,
	`--disable-gpu`,
	`--mute-audio`,
	`--disable-extensions`,
	`--single-process`,
	`--disable-breakpad`,
	`--disable-features=TranslateUI,BlinkGenPropertyTrees`,
	`--disable-ipc-flooding-protection`,
	`--enable-features=NetworkService,NetworkServiceInProcess`,
	"--enable-features=NetworkService",
	`--disable-default-apps`,
	`--disable-notifications`,
	`--disable-webgl`,
	`--disable-blink-features=AutomationControlled`,
	"--ignore-certificate-errors",
	"--ignore-certificate-errors-spki-list",
	"--disable-web-security",
}

const imagesOff = `--blink-settings=imagesEnabled=false`

func TestChromiumArgs_DefaultIsUpstream(t *testing.T) {
	require.Equal(t, upstreamChromiumArgs, chromiumArgs(false, false))
	require.Equal(t, append(append([]string{}, upstreamChromiumArgs...), imagesOff), chromiumArgs(true, false))
}

func TestChromiumArgs_VerifyTLSDropsTheTwoCertificateSwitches(t *testing.T) {
	var want []string

	for _, a := range upstreamChromiumArgs {
		if a == "--ignore-certificate-errors" || a == "--ignore-certificate-errors-spki-list" {
			continue
		}

		want = append(want, a)
	}

	got := chromiumArgs(false, true)

	require.Equal(t, want, got)
	require.NotContains(t, got, "--ignore-certificate-errors")
	require.NotContains(t, got, "--ignore-certificate-errors-spki-list")
	// not a certificate switch: stays, so page behaviour is unchanged
	require.Contains(t, got, "--disable-web-security")

	require.Equal(t, append(append([]string{}, want...), imagesOff), chromiumArgs(true, true))
}

func TestChromiumArgs_ReturnsAFreshSlice(t *testing.T) {
	a := chromiumArgs(false, false)
	a[0] = "changed"

	require.Equal(t, `--start-maximized`, chromiumArgs(false, false)[0])
}
