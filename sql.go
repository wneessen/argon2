// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package argon2

import (
	"database/sql/driver"
	"fmt"
)

// Scan implements the sql.Scanner interface so Argon2 can be read from databases
// transparently. Currently, database types that map to string and []byte are supported.
func (a *Argon2) Scan(src any) error {
	switch src := src.(type) {
	case nil:
		return nil
	case string:
		return a.Scan([]byte(src))
	case []byte:
		if len(src) == 0 {
			return nil
		}
		if len(src) < SerializedSettingsLength {
			return fmt.Errorf("invalid Argon2 hash length, got: %d, expected: %d", len(src), SerializedSettingsLength)
		}
		settings := SettingsFromBytes(src[:SerializedSettingsLength])
		if len(src) != SerializedSettingsLength+int(settings.SaltLength)+int(settings.KeyLength) {
			return fmt.Errorf("invalid Argon2 hash length, got: %d, expected: %d", len(src),
				SerializedSettingsLength+int(settings.SaltLength)+int(settings.KeyLength))
		}
		*a = src
	default:
		return fmt.Errorf("unable to scan type %T into Argon2", src)
	}
	return nil
}

// Value implements the driver.Valuer interface so that Argon2 can be written to databases
// transparently. Currently, Argon2 maps to a byte slice.
func (a Argon2) Value() (driver.Value, error) {
	return []byte(a), nil
}
