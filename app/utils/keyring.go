// Copyright 2026 Tassok Imam Wasiy

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "certman"
	accountName = "master-key"
)

// InitMasterKey generates a secure 32-byte key and stores it in the OS keyring
// It will NOT overwrite an existing key
func InitMasterKey() error {
	_, err := keyring.Get(serviceName, accountName)
	if err == nil {
		return errors.New("Application is already initialized with a master key")
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("failed to generate secure bytes: %w", err)
	}
	masterKeyHex := hex.EncodeToString(keyBytes)

	err = keyring.Set(serviceName, accountName, masterKeyHex)
	if err != nil {
		return fmt.Errorf("failed to store key in OS keyring: %w", err)
	}
	return nil
}

// GetMasterKey retrieves the key from the OS keyring for cryptography
func GetMasterKey() ([]byte, error) {
	keyHex, err := keyring.Get(serviceName, accountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("App not initialized. Please run 'certman init' first")
		}
		return nil, fmt.Errorf("failed to fetch key from OS keyring: %v", err)
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
