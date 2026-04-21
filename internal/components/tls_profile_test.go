// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticProfile(t *testing.T) {
	profile := NewStaticTLSProfile(tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256})
	assert.Equal(t, uint16(tls.VersionTLS12), profile.MinTLSVersion())
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256}, profile.CipherSuites())
	assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"}, profile.CipherSuiteNames())
	assert.Equal(t, "1.2", profile.MinTLSVersionOTEL())
}

func TestStaticProfileTLS13ReturnsNilCiphers(t *testing.T) {
	profile := NewStaticTLSProfile(tls.VersionTLS13, []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384})
	assert.Equal(t, uint16(tls.VersionTLS13), profile.MinTLSVersion())
	assert.Nil(t, profile.CipherSuites(), "TLS 1.3 should return nil for CipherSuites")
	assert.Nil(t, profile.CipherSuiteNames(), "TLS 1.3 should return nil for CipherSuiteNames")
	assert.Equal(t, "1.3", profile.MinTLSVersionOTEL())
}

func TestStaticTLSProfileProvider_GetTLSProfile(t *testing.T) {
	profile := NewStaticTLSProfile(tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	provider := StaticTLSProfileProvider{Profile: profile}

	got, err := provider.GetTLSProfile(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "1.2", got.MinTLSVersionOTEL())
	assert.Equal(t, uint16(tls.VersionTLS12), got.MinTLSVersion())
}

func TestStaticTLSProfileProvider_GetTLSProfile_NilProfile(t *testing.T) {
	provider := StaticTLSProfileProvider{Profile: nil}

	got, err := provider.GetTLSProfile(context.Background())
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestMinTLSVersionGolang(t *testing.T) {
	tests := []struct {
		name       string
		minVersion uint16
		want       string
	}{
		{"TLS 1.0", tls.VersionTLS10, "TLS 1.0"},
		{"TLS 1.1", tls.VersionTLS11, "TLS 1.1"},
		{"TLS 1.2", tls.VersionTLS12, "TLS 1.2"},
		{"TLS 1.3", tls.VersionTLS13, "TLS 1.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := NewStaticTLSProfile(tt.minVersion, nil)
			assert.Equal(t, tt.want, profile.MinTLSVersionGolang())
		})
	}
}

func TestTLSVersionToCollectorFormat(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
		want    string
	}{
		{"TLS 1.0", tls.VersionTLS10, "1.0"},
		{"TLS 1.1", tls.VersionTLS11, "1.1"},
		{"TLS 1.2", tls.VersionTLS12, "1.2"},
		{"TLS 1.3", tls.VersionTLS13, "1.3"},
		{"unknown defaults to 1.2", 0, "1.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TLSVersionToCollectorFormat(tt.version))
		})
	}
}

func TestApplyTLSProfileDefaults(t *testing.T) {
	profile := NewStaticTLSProfile(tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})

	t.Run("applies defaults to empty config", func(t *testing.T) {
		cfg := &TLSConfig{}
		cfg.ApplyTLSProfileDefaults(profile)
		assert.Equal(t, "1.2", cfg.MinVersion)
		assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, cfg.Ciphers)
	})

	t.Run("does not override existing values", func(t *testing.T) {
		cfg := &TLSConfig{MinVersion: "1.3", Ciphers: []string{"existing"}}
		cfg.ApplyTLSProfileDefaults(profile)
		assert.Equal(t, "1.3", cfg.MinVersion)
		assert.Equal(t, []string{"existing"}, cfg.Ciphers)
	})

	t.Run("nil config is safe", func(t *testing.T) {
		var cfg *TLSConfig
		assert.NotPanics(t, func() { cfg.ApplyTLSProfileDefaults(profile) })
	})

	t.Run("nil profile is safe", func(t *testing.T) {
		cfg := &TLSConfig{}
		assert.NotPanics(t, func() { cfg.ApplyTLSProfileDefaults(nil) })
		assert.Empty(t, cfg.MinVersion)
	})
}
