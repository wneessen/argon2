// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"bytes"
	"testing"
)

func TestNewSettings(t *testing.T) {
	t.Run("new settings with default settings", func(t *testing.T) {
		settings := NewSettings(DefaultSettings.Memory, DefaultSettings.Time, DefaultSettings.Threads,
			DefaultSettings.SaltLength, DefaultSettings.KeyLength)
		if settings.Memory != DefaultSettings.Memory {
			t.Errorf("new settings for memory is not as expected: got %d, want %d", settings.Memory,
				DefaultSettings.Memory)
		}
		if settings.Time != DefaultSettings.Time {
			t.Errorf("new settings for time is not as expected: got %d, want %d", settings.Time,
				DefaultSettings.Time)
		}
		if settings.Threads != DefaultSettings.Threads {
			t.Errorf("new settings for threads is not as expected: got %d, want %d", settings.Threads,
				DefaultSettings.Threads)
		}
		if settings.SaltLength != DefaultSettings.SaltLength {
			t.Errorf("new settings for salt length is not as expected: got %d, want %d", settings.SaltLength,
				DefaultSettings.SaltLength)
		}
		if settings.KeyLength != DefaultSettings.KeyLength {
			t.Errorf("new settings for key length is not as expected: got %d, want %d", settings.KeyLength,
				DefaultSettings.KeyLength)
		}
	})
	t.Run("new settings with test settings", func(t *testing.T) {
		settings := NewSettings(testSettings.Memory, testSettings.Time, testSettings.Threads,
			testSettings.SaltLength, testSettings.KeyLength)
		if settings.Memory != testSettings.Memory {
			t.Errorf("new settings for memory is not as expected: got %d, want %d", settings.Memory,
				testSettings.Memory)
		}
		if settings.Time != testSettings.Time {
			t.Errorf("new settings for time is not as expected: got %d, want %d", settings.Time,
				testSettings.Time)
		}
		if settings.Threads != testSettings.Threads {
			t.Errorf("new settings for threads is not as expected: got %d, want %d", settings.Threads,
				testSettings.Threads)
		}
		if settings.SaltLength != testSettings.SaltLength {
			t.Errorf("new settings for salt length is not as expected: got %d, want %d", settings.SaltLength,
				testSettings.SaltLength)
		}
		if settings.KeyLength != testSettings.KeyLength {
			t.Errorf("new settings for key length is not as expected: got %d, want %d", settings.KeyLength,
				testSettings.KeyLength)
		}
	})
}

func TestSettings_Serialize(t *testing.T) {
	t.Run("serializing default settings", func(t *testing.T) {
		serialized := DefaultSettings.Serialize()
		if len(serialized) != SerializedSettingsLength {
			t.Fatal("serialized settings is not the correct length")
		}
		want := []byte{
			0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00,
			0x00, 0x20, 0x00, 0x00, 0x00,
		}
		if !bytes.Equal(serialized, want) {
			t.Errorf("serialized settings is not as expected: got %x, want %x", serialized, want)
		}
	})
	t.Run("serializing test settings", func(t *testing.T) {
		serialized := testSettings.Serialize()
		if len(serialized) != SerializedSettingsLength {
			t.Fatal("serialized settings is not the correct length")
		}
		want := testDerived[:SerializedSettingsLength]
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
		if len(serialized) != SerializedSettingsLength {
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
		settings := NewSettings(123, 5, 8, 123, 321)
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
