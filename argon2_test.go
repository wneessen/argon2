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
		0x00, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x4e, 0x02, 0x30, 0xe2, 0xd5, 0xb3, 0x11, 0x14, 0x82, 0xab, 0xa2, 0x9e, 0xe6, 0x73,
		0x20, 0x05, 0x96, 0x55, 0x41, 0xda, 0xa5, 0x80, 0x0e, 0x6f, 0xbf, 0xb1, 0xc1, 0xdf, 0xec, 0x02,
		0x4c, 0x65, 0xb1, 0xff, 0xf0, 0x7b, 0xbd, 0x30, 0x1e, 0x01, 0x80, 0x60, 0xb7, 0x08, 0x4e, 0x6a,
		0xc0, 0x91,
	}
	testPassPhrase = "Sup3rS3cuReP4$.Phr4$e!"
)

func TestDerive(t *testing.T) {
	t.Run("Argon2ID derive succeeds", func(t *testing.T) {
		derived, err := Derive(testPassPhrase, DefaultSettings)
		if err != nil {
			t.Fatalf("failed to derive hash from password string: %s", err.Error())
		}
		if len(derived) != SerializedSize+int(DefaultSettings.SaltLength)+int(DefaultSettings.KeyLength) {
			t.Fatal("derived hash is not the correct length")
		}
	})
	t.Run("Argon2ID derive fails with broken reader", func(t *testing.T) {
		originalRandReader := rand.Reader
		t.Cleanup(func() {
			rand.Reader = originalRandReader
		})
		rand.Reader = failReader{}
		_, err := Derive(testPassPhrase, DefaultSettings)
		if err == nil {
			t.Fatal("derive should have failed with broken reader")
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("validate succeeds", func(t *testing.T) {
		derived, err := Derive(testPassPhrase, DefaultSettings)
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
