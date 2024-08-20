package recrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"io"
)

var (
	// Define errors
	ErrEncryptionKeyNotInitialized = errors.New("encryption key is not initialized")
	ErrCiphertextTooShort          = errors.New("ciphertext too short")
	ErrFailedToConvertToString     = errors.New("failed to convert database value to string")
	ErrEmptyEncryptionKey          = errors.New("encryption key cannot be empty")
)

// Global variable to store the encryption key
var encryptionKey string

// EncryptedText is a custom type that will automatically handle encryption/decryption
type EncryptedText string

// String returns the plain string representation of EncryptedText
func (et EncryptedText) String() string {
	return string(et)
}

// SetValue converts a plain string into EncryptedText
func SetValue(value string) EncryptedText {
	return EncryptedText(value)
}

// Init initializes the encryption key, returns an error if the key is empty
func Init(key string) error {
	if key == "" {
		return ErrEmptyEncryptionKey
	}
	encryptionKey = key
	return nil
}

// generateSalt creates a new random salt of the given size
func generateSalt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// deriveKey generates a key from a secret key and salt using SHA-256
func deriveKey(secretKey, salt string) []byte {
	hash := sha256.New()
	hash.Write([]byte(secretKey))
	hash.Write([]byte(salt))
	return hash.Sum(nil)
}

// Encrypt encrypts data using AES and returns the salt and ciphertext as a Base64 encoded string
func Encrypt(plainText, secretKey string) (string, error) {
	if secretKey == "" {
		if encryptionKey == "" {
			return "", ErrEncryptionKeyNotInitialized
		}
		secretKey = encryptionKey
	}

	if plainText == "" {
		return "", nil
	}

	salt, err := generateSalt(16)
	if err != nil {
		return "", err
	}

	key := deriveKey(secretKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))

	// Combine salt and ciphertext, then encode with Base64
	combined := salt + base64.StdEncoding.EncodeToString(cipherText)
	return combined, nil
}

// Decrypt decrypts data that was encrypted with the Encrypt function
func Decrypt(encryptedText, secretKey string) (string, error) {
	if secretKey == "" {
		if encryptionKey == "" {
			return "", ErrEncryptionKeyNotInitialized
		}
		secretKey = encryptionKey
	}

	// Check if the encryptedText is empty or too short to contain the salt
	if len(encryptedText) < 24 {
		// Return the original text or a default value
		return encryptedText, nil
	}

	salt := encryptedText[:24] // Assuming the salt size is 16 bytes and encoded in Base64
	cipherText, err := base64.StdEncoding.DecodeString(encryptedText[24:])
	if err != nil {
		return "", err
	}

	key := deriveKey(secretKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", ErrCiphertextTooShort
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

// Implement the GORM Valuer interface to encrypt before storing in the database
func (e EncryptedText) Value() (driver.Value, error) {
	if encryptionKey == "" {
		return nil, ErrEncryptionKeyNotInitialized
	}

	encrypted, err := Encrypt(string(e), encryptionKey)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// Implement the GORM Scanner interface to decrypt after retrieving from the database
func (e *EncryptedText) Scan(value interface{}) error {
	if encryptionKey == "" {
		return ErrEncryptionKeyNotInitialized
	}

	encryptedText, ok := value.(string)
	if !ok {
		return ErrFailedToConvertToString
	}

	decrypted, err := Decrypt(encryptedText, encryptionKey)
	if err != nil {
		return err
	}

	*e = EncryptedText(decrypted)
	return nil
}
