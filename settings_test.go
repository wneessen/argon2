// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"bytes"
	"testing"
)

func TestSettings_Serialize(t *testing.T) {
	t.Run("serializing default settings", func(t *testing.T) {
		serialized := DefaultSettings.Serialize()
		if len(serialized) != SerializedSize {
			t.Fatal("serialized settings is not the correct length")
		}
		want := testDerived[:SerializedSize]
		if !bytes.Equal(serialized, want) {
			t.Errorf("serialized settings is not as expected: got %x, want %x", serialized, want)
		}
	})
	t.Run("serializing custom settings", func(t *testing.T) {
		settings := Settings{
			Memory:     123,
			Time:       5,
			Threads:    8,
			SaltLength: 123,
			KeyLength:  321,
		}
		serialized := settings.Serialize()
		if len(serialized) != SerializedSize {
			t.Fatal("serialized settings is not the correct length")
		}
		want := []byte{
			0x7b, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x7b, 0x00, 0x00, 0x00,
			0x41, 0x01, 0x00, 0x00,
		}
		if !bytes.Equal(serialized, want) {
			t.Fatalf("serialized settings is not as expected: got %x, want %x", serialized, want)
		}
	})
}

func TestSettingsFromBytes(t *testing.T) {
	t.Run("deserializing default settings", func(t *testing.T) {
		settings := DefaultSettings
		serialized := settings.Serialize()
		deserialized := SettingsFromBytes(serialized)
		if settings.Memory != deserialized.Memory {
			t.Errorf("deserialized settings for memory is not as expected: got %d, want %d", deserialized.Memory,
				settings.Memory)
		}
		if settings.Time != deserialized.Time {
			t.Errorf("deserialized settings for time is not as expected: got %d, want %d", deserialized.Time,
				settings.Time)
		}
		if settings.Threads != deserialized.Threads {
			t.Errorf("deserialized settings for threads is not as expected: got %d, want %d", deserialized.Threads,
				settings.Threads)
		}
		if settings.SaltLength != deserialized.SaltLength {
			t.Errorf("deserialized settings for salt length is not as expected: got %d, want %d",
				deserialized.SaltLength, settings.SaltLength)
		}
		if settings.KeyLength != deserialized.KeyLength {
			t.Errorf("deserialized settings for key length is not as expected: got %d, want %d",
				deserialized.KeyLength, settings.KeyLength)
		}
	})
	t.Run("deserializing custom settings", func(t *testing.T) {
		settings := Settings{
			Memory:     123,
			Time:       5,
			Threads:    8,
			SaltLength: 123,
			KeyLength:  321,
		}
		serialized := settings.Serialize()
		deserialized := SettingsFromBytes(serialized)
		if settings.Memory != deserialized.Memory {
			t.Errorf("deserialized settings for memory is not as expected: got %d, want %d", deserialized.Memory,
				settings.Memory)
		}
		if settings.Time != deserialized.Time {
			t.Errorf("deserialized settings for time is not as expected: got %d, want %d", deserialized.Time,
				settings.Time)
		}
		if settings.Threads != deserialized.Threads {
			t.Errorf("deserialized settings for threads is not as expected: got %d, want %d", deserialized.Threads,
				settings.Threads)
		}
		if settings.SaltLength != deserialized.SaltLength {
			t.Errorf("deserialized settings for salt length is not as expected: got %d, want %d",
				deserialized.SaltLength, settings.SaltLength)
		}
		if settings.KeyLength != deserialized.KeyLength {
			t.Errorf("deserialized settings for key length is not as expected: got %d, want %d",
				deserialized.KeyLength, settings.KeyLength)
		}
	})
}

func BenchmarkSettings_Serialize(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DefaultSettings.Serialize()
	}
}

func BenchmarkSettingsFromBytes(b *testing.B) {
	serialized := DefaultSettings.Serialize()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SettingsFromBytes(serialized)
	}
}
