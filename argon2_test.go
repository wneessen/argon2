// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"crypto/rand"
	"errors"
	"testing"
)

func TestDerive(t *testing.T) {
	t.Run("Argon2ID derive succeeds", func(t *testing.T) {
		derived, err := Derive("Sup3rS3cuReP4$.Phr4$e!", DefaultSettings)
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
		_, err := Derive("Sup3rS3cuReP4$.Phr4$e!", DefaultSettings)
		if err == nil {
			t.Fatal("derive should have failed with broken reader")
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("Argon2ID validate succeeds", func(t *testing.T) {
		derived, err := Derive("Sup3rS3cuReP4$.Phr4$e!", DefaultSettings)
		if err != nil {
			t.Fatalf("failed to derive hash from password string: %s", err.Error())
		}
		if !derived.Validate("Sup3rS3cuReP4$.Phr4$e!") {
			t.Fatal("derived hash is not valid")
		}
	})
}

func BenchmarkDerive(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Derive("Sup3rS3cuReP4$.Phr4$e!", DefaultSettings)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (n int, err error) {
	return 0, errors.New("intentionally failed to read")
}
