// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"bytes"
	"testing"
)

var (
	testDerived = []byte{
		0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
		0x00, 0x4e, 0xc0, 0x89, 0x1d, 0x01, 0x67, 0xa5, 0x27, 0xce, 0xea, 0xa5, 0x05, 0x25, 0x39, 0xb1, 0x99,
		0x21, 0xe5, 0xaf, 0x6c, 0xbc, 0x44, 0x2b, 0xdc, 0x83, 0x35, 0xad, 0x1f, 0x00, 0x13, 0xa8, 0xbb, 0x8d,
		0x91, 0x97, 0xab, 0x3b, 0x34, 0xc8, 0x0b, 0x69, 0xce, 0x5b, 0xcc, 0xcb, 0x57, 0xa7, 0x10, 0xf8, 0x2f,
		0x4e, 0x1a, 0x01, 0x99, 0x6f, 0x1b, 0x47, 0xfb, 0x41, 0x43, 0x2a, 0xa8, 0x31, 0xc0,
	}
	testPassPhrase = "Sup3rS3cuReP4$.Phr4$e!"
)

func TestArgon2_Scan(t *testing.T) {
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
