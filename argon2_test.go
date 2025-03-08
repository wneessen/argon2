// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import "testing"

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
}
