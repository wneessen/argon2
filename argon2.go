// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package argon2 provides a simple set of tools to generate and validate Argon2ID hashes using the
// underlying golang.org/x/crypto package.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

type Argon2 []byte

func Derive(password string, settings Settings) ([]byte, error) {
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

func Validate(password string, p []byte) bool {
	settings := SettingsFromBytes(p[:SerializedSize])
	salt := p[SerializedSize : SerializedSize+int(settings.SaltLength)]
	key := p[SerializedSize+int(settings.SaltLength) : SerializedSize+int(settings.SaltLength)+int(settings.KeyLength)]

	derived := argon2.IDKey([]byte(password), salt, settings.Time, settings.Memory, settings.Threads,
		settings.KeyLength)

	return subtle.ConstantTimeCompare(key, derived) == 1
}
