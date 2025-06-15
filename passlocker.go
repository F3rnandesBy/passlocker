package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/crypto/pbkdf2"
)

type Credential struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type EncryptedData struct {
	Nonce      []byte `json:" nonce "`
	CipherText []byte `json:" cipherText "`
}

const (
	dataFile = "vault.json"
	saltFile = "salt.bin"
)

func clearTerminal() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default: // Linux e macOS
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func promptMasterPassword() string {
	fmt.Print("Enter the master password: ")
	reader := bufio.NewReader(os.Stdin)
	pw, _ := reader.ReadString('\n')
	return pw[:len(pw)-1]
}

func deriveKey(masterPassword string, salt []byte) []byte {
	return pbkdf2.Key([]byte(masterPassword), salt, 100000, 32, sha256.New)
}

func encryptData(data []Credential, key []byte) (*EncryptedData, error) {
	plaintext, _ := json.Marshal(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return &EncryptedData{Nonce: nonce, CipherText: ciphertext}, nil
}

func decryptData(enc *EncryptedData, key []byte) ([]Credential, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, enc.Nonce, enc.CipherText, nil)
	if err != nil {
		return nil, err
	}

	var creds []Credential
	json.Unmarshal(plaintext, &creds)
	return creds, nil
}

func saveEncrypted(enc *EncryptedData) error {
	data, _ := json.Marshal(enc)
	return ioutil.WriteFile(dataFile, data, 0600)
}

func loadEncrypted() (*EncryptedData, error) {
	data, err := ioutil.ReadFile(dataFile)
	if err != nil {
		return nil, err
	}
	var enc EncryptedData
	json.Unmarshal(data, &enc)
	return &enc, nil
}

func saveSalt(salt []byte) error {
	return ioutil.WriteFile(saltFile, salt, 0600)
}

func loadSalt() ([]byte, error) {
	return ioutil.ReadFile(saltFile)
}

func main() {
	master := promptMasterPassword()

	var salt []byte
	if _, err := os.Stat(saltFile); os.IsNotExist(err) {
		salt = make([]byte, 16)
		rand.Read(salt)
		saveSalt(salt)
	} else {
		salt, _ = loadSalt()
	}

	key := deriveKey(master, salt)

	var creds []Credential
	if _, err := os.Stat(dataFile); err == nil {
		enc, _ := loadEncrypted()
		creds, _ = decryptData(enc, key)
	}

	for {
		var op int
		fmt.Print("\n[1] - Listar senhas\n[2] - Adicionar\n[3] - Sair\n")
		fmt.Print("[~] : ")
		fmt.Scan(&op)
		switch op {
		case 1:
			clearTerminal()
			if creds != nil {
				for _, c := range creds {
					fmt.Printf("[#] - %s | %s | %s\n", c.Service, c.Username, c.Password)
				}
			} else {
				fmt.Print("No Data!")
			}
		case 2:
			clearTerminal()
			var s, u, p string
			fmt.Print("Service: ")
			fmt.Scan(&s)
			fmt.Print("User/Email: ")
			fmt.Scan(&u)
			fmt.Print("Password: ")
			fmt.Scan(&p)
			creds = append(creds, Credential{Service: s, Username: u, Password: p})
			enc, _ := encryptData(creds, key)
			saveEncrypted(enc)
		case 3:
			return
		}
	}
}
