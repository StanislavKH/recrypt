package recrypt

import (
	"testing"
)

// TestInit ensures that the Init function correctly sets the encryption key
func TestInit(t *testing.T) {
	err := Init("test-secret-key")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if encryptionKey != "test-secret-key" {
		t.Fatalf("Expected 'test-secret-key', got %v", encryptionKey)
	}
}

// TestEncryptDecrypt ensures that Encrypt and Decrypt work as expected
func TestEncryptDecrypt(t *testing.T) {
	Init("test-secret-key")

	plainText := "Sensitive Data"
	encryptedText, err := Encrypt(plainText, "")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decryptedText, err := Decrypt(encryptedText, "")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decryptedText != plainText {
		t.Fatalf("Expected decrypted text to be %v, got %v", plainText, decryptedText)
	}
}

// TestEncryptWithoutInit ensures that Encrypt returns an error when the key is not initialized
func TestEncryptWithoutInit(t *testing.T) {
	encryptionKey = "" // Reset encryption key
	_, err := Encrypt("Sensitive Data", "")
	if err != ErrEncryptionKeyNotInitialized {
		t.Fatalf("Expected ErrEncryptionKeyNotInitialized, got %v", err)
	}
}

// TestDecryptWithoutInit ensures that Decrypt returns an error when the key is not initialized
func TestDecryptWithoutInit(t *testing.T) {
	encryptionKey = "" // Reset encryption key
	_, err := Decrypt("EncryptedData", "")
	if err != ErrEncryptionKeyNotInitialized {
		t.Fatalf("Expected ErrEncryptionKeyNotInitialized, got %v", err)
	}
}

// TestGORMIntegration tests the GORM Valuer and Scanner interfaces
func TestGORMIntegration(t *testing.T) {
	Init("test-secret-key")

	plainText := "Sensitive Data"
	encryptedText := SetValue(plainText)

	// Test Valuer interface
	val, err := encryptedText.Value()
	if err != nil {
		t.Fatalf("Value failed: %v", err)
	}

	// Convert val to string to simulate database retrieval
	valStr, ok := val.(string)
	if !ok {
		t.Fatalf("Expected val to be string, got %T", val)
	}

	// Test Scanner interface
	var scannedText EncryptedText
	err = scannedText.Scan(valStr)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if scannedText.String() != plainText {
		t.Fatalf("Expected scanned text to be %v, got %v", plainText, scannedText.String())
	}
}

// TestEmptyPlainText ensures that Encrypt returns an empty string when given empty plain text
func TestEmptyPlainText(t *testing.T) {
	Init("test-secret-key")

	plainText := ""
	encryptedText, err := Encrypt(plainText, "")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encryptedText != "" {
		t.Fatalf("Expected empty encrypted text, got %v", encryptedText)
	}
}

// TestGORMValuerAndScannerErrors tests error handling in GORM Valuer and Scanner interfaces
func TestGORMValuerAndScannerErrors(t *testing.T) {
	Init("test-secret-key")

	// Test with encryption key not initialized
	encryptionKey = ""

	var et EncryptedText
	_, err := et.Value()
	if err != ErrEncryptionKeyNotInitialized {
		t.Fatalf("Expected ErrEncryptionKeyNotInitialized, got %v", err)
	}

	// Test with invalid Scan value type
	encryptionKey = "test-secret-key"
	err = et.Scan(12345) // Invalid type
	if err != ErrFailedToConvertToString {
		t.Fatalf("Expected ErrFailedToConvertToString, got %v", err)
	}
}
