package vault

import (
    "os/exec"
	"bytes"
	"fmt"
	"os"
)

func EncryptWithAnsibleVault(vaultPasswordFile, data, variableName string, path string) (error) {
    cmd := exec.Command("ansible-vault", "encrypt_string", "--vault-password-file", vaultPasswordFile, data, "--name", variableName)

    var out bytes.Buffer
    cmd.Stdout = &out

    err := cmd.Run()
    if err != nil {
		fmt.Printf("failed to encrypt file: %v", err)
        return err
    }

	// Write the encrypted output to the file at outputPath
    err = os.WriteFile(path+"/"+variableName+".yaml", out.Bytes(), 0644)
    if err != nil {
        fmt.Printf("failed to write encrypted data to file: %v\n", err)
        return err
    }

	return nil
}

// decryptAnsibleVaultFile uses ansible-vault to decrypt a file and returns its content.
func DecryptAnsibleVaultFile(filePath, vaultPasswordFile string) (string, error) {
    cmd := exec.Command("ansible-vault", "view", filePath, "--vault-password-file", vaultPasswordFile)

    var out bytes.Buffer
    cmd.Stdout = &out

    err := cmd.Run()
    if err != nil {
        return "", fmt.Errorf("failed to decrypt file: %v", err)
    }

    return out.String(), nil
}

