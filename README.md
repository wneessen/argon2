# Argon2

## Overview
This Go package provides a simple set of tools to generate and validate Argon2id password hashes using 
the [golang.org/x/crypto/argon2](https://github.com/golang/crypto/tree/master/argon2) package.

It also includes utilities for managing Argon2 hashing settings and supports seamless integration with 
SQL databases by implementing the `sql.Scanner` and `driver.Value` interfaces.

## Features
- Generate Argon2id password hashes.
- Validate hashed passwords.
- Manage and serialize Argon2 settings.
- Store and retrieve hashes from SQL databases.

## Usage

### Generating a Hash
```go
package main

import (
	"fmt"
    
	"github.com/wneessen/argon2"
)

func main() {
	hash, err := argon2.Derive("my_secure_password", argon2.DefaultSettings)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated Hash: %x\n", hash)
}
```

### Validating a Password
```go
package main

import (
	"fmt"

	"github.com/wneessen/argon2"
)

func main() {
	hash, err := argon2.Derive("my_secure_password", argon2.DefaultSettings)
	if err != nil {
		panic(err)
	}
	isValid := hash.Validate("my_secure_password")
	if isValid {
		fmt.Println("Password is valid!")
	} else {
		fmt.Println("Invalid password!")
	}
}
```

### Using Custom Argon2 Settings
```go
package main

import (
	"fmt"

	"github.com/wneessen/argon2"
)

func main() {
	settings := argon2.NewSettings(65536, 3, 2, 32, 32)
	hash, err := argon2.Derive("my_secure_password", settings)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated Hash: %x\n", hash)
}
```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author
Developed by Winni Neessen <wn@neessen.dev>