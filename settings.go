// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"encoding/binary"
)

// Settings holds the configuration for generating an Argon2 hash.
//
// This struct contains the parameters required for Argon2 hashing, including memory cost,
// time cost, parallelism, salt length, and key length. These settings are used during both
// hash derivation (in the Derive function) and validation (in the `Validate` function) to
// configure the Argon2 algorithm according to the user's requirements.
//
// Fields:
//   - Memory: The memory cost for Argon2, specified in kilobytes. This determines how much
//     memory Argon2 will use during the hash computation.
//   - Time: The time cost for Argon2, specified as the number of iterations. This affects
//     the computation time for generating or validating the hash.
//   - Threads: The number of parallel threads to use during the hash computation. This affects
//     the speed of the hash calculation but also impacts performance based on the hardware.
//   - SaltLength: The length of the random salt in bytes. The salt is used to ensure that
//     the same password results in different hashes when hashed multiple times with different salts.
//   - KeyLength: The length of the derived key in bytes. This is the length of the hash output
//     that will be used as the final result after Argon2 computation.
type Settings struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

// SerializedSize defines the fixed size in bytes required to serialize the Settings struct using
// little-endian encoding.
const SerializedSize = 18

// DefaultSettings is the default configuration for Argon2 hashing.
//
// This variable provides default values for the `Settings` struct that can be used
// in hash derivation and validation when custom settings are not specified. The values
// are chosen to provide a reasonable balance between security and performance, suitable
// for most general use cases.
//
// The default settings are as follows:
//   - Memory: 128 MB (128 * 1024 KB)
//   - Time: 3 iterations
//   - Threads: 4 parallel threads
//   - SaltLength: 32 bytes for the salt
//   - KeyLength: 32 bytes for the derived key
var DefaultSettings = Settings{
	Memory:     128 * 1024,
	Time:       3,
	Threads:    4,
	SaltLength: 32,
	KeyLength:  32,
}

// Serialize converts the Settings struct into a byte slice.
//
// This method serializes the fields of the Settings struct into a byte slice using
// little-endian byte order. The resulting byte slice can be used for storage or
// transmission of the settings in a compact format. The serialized byte slice contains
// the following fields in this order:
//   - Memory (4 bytes)
//   - Time (4 bytes)
//   - Threads (2 bytes, converted to uint16)
//   - SaltLength (4 bytes)
//   - KeyLength (4 bytes)
//
// The total size of the resulting byte slice is determined by the constant `SerializedSize`.
//
// Returns:
//   - A byte slice containing the serialized Settings struct in little-endian byte order.
func (s Settings) Serialize() []byte {
	buffer := make([]byte, SerializedSize)
	binary.LittleEndian.PutUint32(buffer[0:4], s.Memory)
	binary.LittleEndian.PutUint32(buffer[4:8], s.Time)
	binary.LittleEndian.PutUint16(buffer[8:10], uint16(s.Threads))
	binary.LittleEndian.PutUint32(buffer[10:14], s.SaltLength)
	binary.LittleEndian.PutUint32(buffer[14:18], s.KeyLength)
	return buffer
}

// SettingsFromBytes deserializes a byte slice into a Settings struct.
//
// This function takes a byte slice representing serialized `Settings` data and
// converts it back into a `Settings` struct. The byte slice must contain the serialized
// data in little-endian byte order, with the following field sizes and order:
//   - Memory (4 bytes)
//   - Time (4 bytes)
//   - Threads (2 bytes, converted from uint16 to uint8)
//   - SaltLength (4 bytes)
//   - KeyLength (4 bytes)
//
// The function returns a `Settings` struct with the values extracted from the byte slice.
//
// Parameters:
//   - p: A byte slice containing the serialized Settings data in little-endian byte order.
//
// Returns:
//   - A Settings struct populated with the values extracted from the byte slice.
func SettingsFromBytes(p []byte) Settings {
	return Settings{
		Memory:     binary.LittleEndian.Uint32(p[0:4]),
		Time:       binary.LittleEndian.Uint32(p[4:8]),
		Threads:    uint8(binary.LittleEndian.Uint16(p[8:10])),
		SaltLength: binary.LittleEndian.Uint32(p[10:14]),
		KeyLength:  binary.LittleEndian.Uint32(p[14:18]),
	}
}
