package scrapemateapp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gosom/scrapemate"
	"github.com/gosom/scrapemate/mock"
)

func TestVerifyTLS_DefaultsToOff(t *testing.T) {
	cfg, err := NewConfig([]scrapemate.ResultWriter{&mock.MockResultWriter{}})
	require.NoError(t, err)

	require.False(t, cfg.VerifyTLS, "upstream behaviour: no certificate verification option unless asked for")
	require.Empty(t, stealthOptions(cfg))
}

func TestVerifyTLS_OptionTurnsItOn(t *testing.T) {
	cfg, err := NewConfig(
		[]scrapemate.ResultWriter{&mock.MockResultWriter{}},
		WithStealth("firefox"),
		WithVerifyTLS(true),
	)
	require.NoError(t, err)

	require.True(t, cfg.VerifyTLS)
	require.Len(t, stealthOptions(cfg), 1, "the stealth fetcher receives the verification option")
}

func TestVerifyTLS_FalseKeepsItOff(t *testing.T) {
	cfg, err := NewConfig(
		[]scrapemate.ResultWriter{&mock.MockResultWriter{}},
		WithVerifyTLS(true),
		WithVerifyTLS(false),
	)
	require.NoError(t, err)

	require.False(t, cfg.VerifyTLS)
	require.Empty(t, stealthOptions(cfg))
}
