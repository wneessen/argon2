// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package argon2 provides a simple set of tools to generate and validate Argon2id hashes using the
// underlying golang.org/x/crypto package.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2 represents a slice of bytes used for storing Argon2 password hash or derived key.
type Argon2 []byte

// Derive generates an Argon2id hash using the provided password and settings.
//
// This function generates a random salt of the specified length from the provided
// settings and serializes the settings to create a hash. It then derives an Argon2id
// key based on the password, salt, and settings, and combines the serialized settings,
// salt, and derived key into a final hash. The resulting hash is returned along with
// any errors encountered during the process.
//
// Parameters:
//   - password: The password to derive the key from. This should be a string.
//   - settings: A Settings struct containing parameters for Argon2 hash generation.
//
// Returns:
//   - A byte slice containing the concatenated serialized settings, salt, and derived key.
//   - An error if any issues occur during salt generation or key derivation.
func Derive(password string, settings Settings) (Argon2, error) {
	salt := make([]byte, settings.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	serialized := settings.Serialize()
	hashSize := SerializedSize + int(settings.SaltLength+settings.KeyLength)
	hash := make([]byte, hashSize)
	copy(hash, serialized)
	copy(hash[SerializedSize:], salt)
	key := argon2.IDKey([]byte(password), salt, settings.Time, settings.Memory, settings.Threads,
		settings.KeyLength)
	copy(hash[SerializedSize+int(settings.SaltLength):hashSize], key)

	return hash, nil
}

// Validate checks if the provided password matches the Argon2 hash.
//
// This method extracts the serialized settings, salt, and the derived key from the
// Argon2 hash. It then derives a new key using the given password, salt, and settings,
// and compares it with the original key stored in the Argon2 hash using constant-time
// comparison to prevent timing attacks.
//
// Parameters:
//   - password: The password to validate against the Argon2 hash.
//
// Returns:
//   - A boolean indicating whether the provided password is valid. Returns true if the
//     derived key matches the key in the Argon2 hash, false otherwise.
func (a Argon2) Validate(password string) bool {
	settings := SettingsFromBytes(a[:SerializedSize])
	salt := a[SerializedSize : SerializedSize+int(settings.SaltLength)]
	key := a[SerializedSize+int(settings.SaltLength) : SerializedSize+int(settings.SaltLength)+int(settings.KeyLength)]

	derived := argon2.IDKey([]byte(password), salt, settings.Time, settings.Memory, settings.Threads,
		settings.KeyLength)

	return subtle.ConstantTimeCompare(key, derived) == 1
}
