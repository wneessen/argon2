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
	hashSize := SerializedSettingsLength + int(settings.SaltLength+settings.KeyLength)
	hash := make([]byte, hashSize)
	copy(hash, serialized)
	copy(hash[SerializedSettingsLength:], salt)
	key := argon2.IDKey([]byte(password), salt, settings.Time, settings.Memory, settings.Threads,
		settings.KeyLength)
	copy(hash[SerializedSettingsLength+int(settings.SaltLength):hashSize], key)

	return hash, nil
}

// Salt extracts and returns the salt from the Argon2 hash.
//
// This method retrieves the salt used during the Argon2 key derivation process.
// If the stored Argon2 hash is shorter than the expected serialized settings length,
// it returns an empty byte slice.
//
// Steps performed:
//   - Copies the Argon2 hash to avoid mutating the original data.
//   - Checks if the data length is valid; if not, returns an empty slice.
//   - Extracts the Settings from the serialized portion of the hash.
//   - Returns the salt portion of the hash based on the extracted settings.
//
// Returns:
//   - A byte slice containing the salt extracted from the Argon2 hash.
//   - If the stored data is invalid or too short, an empty slice is returned.
func (a Argon2) Salt() []byte {
	data := make([]byte, len(a))
	copy(data, a)

	if len(data) < SerializedSettingsLength {
		return []byte{}
	}

	settings := SettingsFromBytes(data[:SerializedSettingsLength])
	return data[SerializedSettingsLength : SerializedSettingsLength+int(settings.SaltLength)]
}

// Key extracts and returns the derived key from the Argon2 hash.
//
// This method retrieves the key that was generated during the Argon2 key derivation process.
// If the stored Argon2 hash is shorter than the expected serialized settings length,
// it returns an empty byte slice.
//
// Steps performed:
//   - Copies the Argon2 hash to avoid modifying the original data.
//   - Checks if the data length is valid; if not, returns an empty slice.
//   - Extracts the Settings from the serialized portion of the hash.
//   - Returns the derived key portion of the hash based on the extracted settings.
//
// Returns:
//   - A byte slice containing the derived key extracted from the Argon2 hash.
//   - If the stored data is invalid or too short, an empty slice is returned.
func (a Argon2) Key() []byte {
	data := make([]byte, len(a))
	copy(data, a)

	if len(data) < SerializedSettingsLength {
		return []byte{}
	}

	settings := SettingsFromBytes(data[:SerializedSettingsLength])
	return data[SerializedSettingsLength+int(settings.SaltLength) : SerializedSettingsLength+int(settings.SaltLength+settings.KeyLength)]
}

// Validate verifies whether the given password matches the Argon2 hash.
//
// This method takes a plaintext password and checks if it matches the stored Argon2 hash.
// It ensures that even if an invalid or zero-length byte slice is passed, the function
// still executes the Argon2 key derivation function (KDF) with default settings to prevent
// timing attacks.
//
// Steps performed:
//   - Copies the Argon2 hash data to prevent mutation.
//   - If the input data is too short or empty, it falls back to `DefaultSettings` and
//     generates a random salt and key.
//   - If the stored hash does not match the expected structure (e.g., incorrect key length),
//     it regenerates random values to avoid leaking information about tampered or invalid hashes.
//   - Computes the Argon2 key from the provided password using the extracted settings and salt.
//   - Compares the derived key with the stored key using subtle.ConstantTimeCompare.
//
// Parameters:
//   - password: The plaintext password to validate against the Argon2 hash.
//
// Returns:
//   - true if the password is valid and matches the stored Argon2 hash.
//
// Security considerations:
//   - Even when an invalid hash is provided, the function executes the Argon2 KDF to
//     prevent timing attacks that could hint at the validity of stored data.
//   - Uses constant-time comparison to mitigate side-channel attacks.
func (a Argon2) Validate(password string) bool {
	data := make([]byte, len(a))
	copy(data, a)

	// If an invalid length or zero byte slice is passed, we fall back to the DefaultSettings.
	// This is crucial, so that we do not skip the CPU and memory consuption of the KDF and
	// potentially run into a timing attack.
	if len(data) < SerializedSettingsLength {
		data = make([]byte, SerializedSettingsLength+int(DefaultSettings.SaltLength+DefaultSettings.KeyLength))
		copy(data, DefaultSettings.Serialize())
		_, _ = io.ReadFull(rand.Reader, data[SerializedSettingsLength:])
	}

	// If the byte slice does not provide the expected key length we can assume that the data
	// is either corrupted or tampered with. In this case we also have potential for a timing
	// attack and apply the same logic as with empty data and always execute the Argon2 KDF.
	settings := SettingsFromBytes(data[:SerializedSettingsLength])
	if len(data) != SerializedSettingsLength+int(settings.SaltLength+settings.KeyLength) {
		data = make([]byte, SerializedSettingsLength+int(settings.SaltLength+settings.KeyLength))
		copy(data, data[:SerializedSettingsLength])
		_, _ = io.ReadFull(rand.Reader, data[SerializedSettingsLength:])
	}

	salt := data[SerializedSettingsLength : SerializedSettingsLength+int(settings.SaltLength)]
	key := data[SerializedSettingsLength+int(settings.SaltLength) : SerializedSettingsLength+int(settings.SaltLength+settings.KeyLength)]
	derived := argon2.IDKey([]byte(password), salt, settings.Time, settings.Memory, settings.Threads,
		settings.KeyLength)

	return subtle.ConstantTimeCompare(key, derived) == 1
}
