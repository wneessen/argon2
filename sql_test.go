// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"bytes"
	"testing"
)

func TestArgon2_Scan(t *testing.T) {
	t.Run("scan with valid byte array", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan(testDerived); err != nil {
			t.Fatalf("failed to scan byte array: %s", err)
		}
		if argon == nil {
			t.Fatal("argon2 is nil after scan")
		}
		if !bytes.Equal(argon, testDerived) {
			t.Errorf("argon2 from scan does not match expected value, got: %x, want: %x", argon, testDerived)
		}
		if !argon.Validate(testPassPhrase) {
			t.Errorf("argon2 from scan does not match expected value, got: %x, want: %x", argon, testDerived)
		}
	})
	t.Run("scan with nil value", func(t *testing.T) {
		var argon Argon2
		err := (&argon).Scan(nil)
		if err != nil {
			t.Fatal(err)
		}
		if argon != nil {
			t.Fatal("argon2 is not nil after scan")
		}
	})
	t.Run("scan with zero byte array", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan([]byte{}); err != nil {
			t.Fatalf("failed to scan byte array: %s", err)
		}
		if argon != nil {
			t.Fatal("argon2 is not nil after scan")
		}
	})
	t.Run("scan with invalid byte array", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan([]byte{0x00, 0x00, 0x00}); err == nil {
			t.Fatal("scan should have failed with invalid byte array")
		}
	})
	t.Run("scan with too short byte array", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan(testDerived[:len(testDerived)-1]); err == nil {
			t.Fatal("scan should have failed with too short byte array")
		}
	})
	t.Run("scan with valid string", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan(string(testDerived)); err != nil {
			t.Fatalf("failed to scan string: %s", err)
		}
		if argon == nil {
			t.Fatal("argon2 is nil after scan")
		}
		if !bytes.Equal(argon, testDerived) {
			t.Errorf("argon2 from scan does not match expected value, got: %x, want: %x", argon, testDerived)
		}
		if !argon.Validate(testPassPhrase) {
			t.Errorf("argon2 from scan does not match expected value, got: %x, want: %x", argon, testDerived)
		}
	})
	t.Run("scan with unsupported type", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan(123); err == nil {
			t.Fatal("scan should have failed with unsupported type")
		}
	})
}

func TestArgon2_Value(t *testing.T) {
	t.Run("value with nil value", func(t *testing.T) {
		var argon Argon2
		value, _ := argon.Value()
		if !bytes.Equal(value.([]byte), []byte{}) {
			t.Fatal("argon2 with nil value did not return empty byte slice")
		}
	})
	t.Run("value with valid value", func(t *testing.T) {
		var argon Argon2
		if err := (&argon).Scan(testDerived); err != nil {
			t.Fatalf("failed to scan byte array: %s", err)
		}
		value, _ := argon.Value()
		if !bytes.Equal(value.([]byte), testDerived) {
			t.Errorf("argon2 value does not match expected value, got: %x, want: %x", value, testDerived)
		}
		castArgon := Argon2(value.([]byte))
		if !castArgon.Validate(testPassPhrase) {
			t.Errorf("argon2 value does not match the argon2id validation, got: %x, want: %x", castArgon, testDerived)
		}
	})
}
