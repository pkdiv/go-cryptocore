# go-cryptocore

`go-cryptocore` is a Go library providing robust cryptographic primitives and utilities. It currently features a simplified interface for Argon2id key derivation.

## Key Derivation Functions (KDF)

### Argon2id

Argon2id is a hybrid of Argon2i and Argon2d, providing resistance against both side-channel attacks and GPU-based password cracking. It is the recommended algorithm for password hashing and key derivation.

#### `Argon2idKeyDerivation`

The `Argon2idKeyDerivation` function provides an easy way to derive a cryptographic key from a password with sensible defaults and flexible configuration.

##### Basic Usage

To derive a key using the default parameters (3 iterations, 64MB memory, 4 threads, 32-byte key):

```go
package main

import (
	"fmt"
	"log"

	"github.com/pkdiv/go-cryptocore/kdf"
)

func main() {
	password := "user-secure-password"

	// Derive the key
	params, err := kdf.Argon2idKeyDerivation(password)
	if err != nil {
		log.Fatalf("Failed to derive key: %v", err)
	}

	fmt.Printf("Derived Key (base64): %x\n", params.Kek)
	fmt.Printf("Salt (base64): %x\n", params.Salt)
}
```

##### Advanced Usage (Custom Options)

You can customize the Argon2id parameters using functional options:

```go
params, err := kdf.Argon2idKeyDerivation(password,
    kdf.WithTime(5),            // 5 iterations
    kdf.WithMemory(128 * 1024), // 128MB RAM
    kdf.WithThreads(8),         // 8 parallel threads
    kdf.WithKeyLen(64),        // 64-byte output key
)
```

##### Parameters Struct

The function returns an `Argon2idParams` struct, which contains both the generated key and the parameters used for derivation:

```go
type Argon2idParams struct {
	Kek     []byte // The derived Key Encryption Key
	Salt    []byte // The random salt generated (16 bytes)
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory usage in KiB
	Threads uint8  // Number of threads
	KeyLen  uint32 // Length of the generated key
}
```

> [!NOTE]
> The function automatically generates a random 16-byte salt for each call using `crypto/rand`. You should store both the `Salt` and the parameters (`Time`, `Memory`, `Threads`, `KeyLen`) alongside the hashed value to be able to re-derive the key later for verification.

## Installation

```bash
go get github.com/pkdiv/go-cryptocore.git
```

## Default Parameters


-   **Memory**: 64 MB (65536)
-   **Iterations**: 3
-   **Parallelism**: 4 (or number of available cores)
-   **Key Length**: 32 bytes

Higher values can be used for increased security at the cost of performance and latency.
