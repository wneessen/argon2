// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"crypto/rand"
	"errors"
	"testing"
)

var (
	testDerived = []byte{
		0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0xf2, 0xe0, 0x9f, 0xac, 0xf9, 0xe2, 0x1a, 0x22, 0x68, 0x94, 0xa1, 0xd9, 0x7b, 0xd6,
		0xcf, 0xfb, 0xae, 0xbd, 0x76, 0x21, 0x80, 0xc1, 0x7c, 0x87, 0xbd, 0xbd, 0x57, 0xa9, 0xef, 0xb2,
		0xc9, 0xb7, 0x9f, 0x81, 0x0d, 0xaf, 0x4f, 0xab, 0x55, 0xb6, 0x7a, 0x70, 0x5f, 0xed, 0x52, 0x21,
		0xdf, 0xb3,
	}
	testPassPhrase = "Sup3rS3cuReP4$.Phr4$e!"
	testSettings   = Settings{
		Memory:     256 * 1024,
		Time:       1,
		Threads:    4,
		SaltLength: 16,
		KeyLength:  32,
	}
)

func TestDerive(t *testing.T) {
	t.Run("Argon2ID derive succeeds with default settings", func(t *testing.T) {
		derived, err := Derive(testPassPhrase, DefaultSettings)
		if err != nil {
			t.Fatalf("failed to derive hash from password string: %s", err.Error())
		}
		if len(derived) != SerializedSettingsLength+int(DefaultSettings.SaltLength)+int(DefaultSettings.KeyLength) {
			t.Fatal("derived hash is not the correct length")
		}
	})
	t.Run("Argon2ID derive succeeds with test settings", func(t *testing.T) {
		derived, err := Derive(testPassPhrase, testSettings)
		if err != nil {
			t.Fatalf("failed to derive hash from password string: %s", err.Error())
		}
		if len(derived) != SerializedSettingsLength+int(testSettings.SaltLength+testSettings.KeyLength) {
			t.Fatal("derived hash is not the correct length")
		}
	})
	t.Run("Argon2ID derive fails with broken reader", func(t *testing.T) {
		originalRandReader := rand.Reader
		t.Cleanup(func() {
			rand.Reader = originalRandReader
		})
		rand.Reader = failReader{}
		_, err := Derive(testPassPhrase, testSettings)
		if err == nil {
			t.Fatal("derive should have failed with broken reader")
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("validate succeeds", func(t *testing.T) {
		derived, err := Derive(testPassPhrase, testSettings)
		if err != nil {
			t.Fatalf("failed to derive hash from password string: %s", err.Error())
		}
		if !derived.Validate(testPassPhrase) {
			t.Fatal("derived hash is not valid but should be")
		}
	})
	t.Run("validate with static values succeeds", func(t *testing.T) {
		argon := Argon2(testDerived)
		if !argon.Validate(testPassPhrase) {
			t.Fatal("derived hash is not valid but should be")
		}
	})
	t.Run("validate on nil", func(t *testing.T) {
		var argon Argon2
		if argon.Validate(testPassPhrase) {
			t.Fatal("validation on nil should have failed")
		}
	})
	t.Run("validate on invalid hash", func(t *testing.T) {
		argon := Argon2(testDerived[:len(testDerived)-2])
		if argon.Validate(testPassPhrase) {
			t.Fatal("validation on invalid hash should have failed")
		}
	})
}

func BenchmarkDerive(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Derive(testPassPhrase, DefaultSettings)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (n int, err error) {
	return 0, errors.New("intentionally failed to read")
}
