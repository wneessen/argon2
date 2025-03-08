// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"encoding/binary"
)

// Settings defines a configuration for memory, time, threads, salt length, and key length of the Argon2ID hash
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

// DefaultSettings defines the default configuration for the Settings struct, including memory, time, threads,
// salt length, and key length.
var DefaultSettings = Settings{
	Memory:     128 * 1024,
	Time:       3,
	Threads:    4,
	SaltLength: 32,
	KeyLength:  32,
}

// Serialize converts the Settings struct into a byte slice using little-endian encoding for efficient storage
// or transfer.
func (s Settings) Serialize() []byte {
	buffer := make([]byte, SerializedSize)
	binary.LittleEndian.PutUint32(buffer[0:4], s.Memory)
	binary.LittleEndian.PutUint32(buffer[4:8], s.Time)
	binary.LittleEndian.PutUint16(buffer[8:10], uint16(s.Threads))
	binary.LittleEndian.PutUint32(buffer[10:14], s.SaltLength)
	binary.LittleEndian.PutUint32(buffer[14:18], s.KeyLength)
	return buffer
}

// SettingsFromBytes reconstructs a Settings struct from a given little-endian encoded byte slice.
func SettingsFromBytes(p []byte) Settings {
	return Settings{
		Memory:     binary.LittleEndian.Uint32(p[0:4]),
		Time:       binary.LittleEndian.Uint32(p[4:8]),
		Threads:    uint8(binary.LittleEndian.Uint16(p[8:10])),
		SaltLength: binary.LittleEndian.Uint32(p[10:14]),
		KeyLength:  binary.LittleEndian.Uint32(p[14:18]),
	}
}
