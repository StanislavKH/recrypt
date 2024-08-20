
# Recrypt - A Go Library for Secure Text Encryption and Decryption

## Overview

`Recrypt` is a Go package designed to simplify the process of encrypting and decrypting text data using AES encryption. It provides an easy-to-use API to securely handle sensitive information, such as passwords or private data, within your Go applications. The package is particularly useful for integrating encryption into your database layer, ensuring that sensitive data is stored securely.

## Features

- **AES Encryption**: Secure your data using AES encryption with a customizable secret key.
- **Automatic Encryption/Decryption**: The `EncryptedText` type automatically handles encryption before storing and decryption after retrieving data from the database.
- **GORM Integration**: Seamlessly integrates with GORM by implementing the `driver.Valuer` and `sql.Scanner` interfaces, enabling encrypted storage in relational databases.
- **Configurable Encryption Key**: The encryption key can be set at initialization, allowing for flexible and secure configuration management.
- **Salt Generation**: Adds an extra layer of security by generating and incorporating a salt into the encryption process.
- **Error Handling**: Comprehensive error handling ensures that encryption and decryption processes are robust and reliable.

## Getting Started

### Installation

To install `Recrypt`, use the following command:

```bash
go get -u github.com/StanislavKH/recrypt
```

### Usage

1. **Initialize the Encryption Key**:

    ```go
    err := recrypt.Init("your-secret-key")
    if err != nil {
        log.Fatal(err)
    }
    ```

2. **Encrypting Text**:

    ```go
    encryptedText, err := recrypt.Encrypt("Sensitive Data", "")
    if err != nil {
        log.Fatal(err)
    }
    ```

    **Explanation**: In this example, the `Encrypt` function is used to encrypt the string `"Sensitive Data"`. The second argument, an empty string `""`, indicates that the encryption key should use the globally initialized key set by the `Init` function. If the package has already been initialized with a secret key using `recrypt.Init("your-secret-key")`, that key will be used automatically. If you want to use a different key for this specific encryption operation, you can provide it instead of `""`.

3. **Decrypting Text**:

    ```go
    decryptedText, err := recrypt.Decrypt(encryptedText, "")
    if err != nil {
        log.Fatal(err)
    }
    ```

    **Explanation**: Similarly, in this example, the `Decrypt` function is used to decrypt the previously encrypted text. The second argument is an empty string `""`, meaning the decryption will use the globally initialized key. If you need to decrypt the text with a different key, you can pass that key as the second argument.

4. **Using with GORM**:

    ```go
    type User struct {
        Name     string
        Password recrypt.EncryptedText
    }

    // Store a new user with an encrypted password
    db.Create(&User{Name: "John Kramer", CreditCardNumber: recrypt.SetValue("0000-0000-0000-0000")})
    ```

## Error Handling

The package provides several error types that help in identifying issues during encryption and decryption:

- `ErrEncryptionKeyNotInitialized`: Thrown when trying to encrypt/decrypt without initializing the encryption key.
- `ErrCiphertextTooShort`: Thrown when the ciphertext is too short to be valid.
- `ErrFailedToConvertToString`: Thrown when the database value cannot be converted to a string.
- `ErrEmptyEncryptionKey`: Thrown when an attempt is made to initialize with an empty encryption key.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
