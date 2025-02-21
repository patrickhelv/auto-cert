package vault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

func EncryptWithAnsibleVault(vaultPasswordFile string, data string, typeName string, path string, env bool, variableName string) error {
	
	var cmd *exec.Cmd
	if env{
		cmd = exec.Command("ansible-vault", "encrypt_string", "--name", typeName, data)
	}else{
		cmd = exec.Command("ansible-vault", "encrypt_string", "--vault-password-file", vaultPasswordFile, data, "--name", typeName)
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out // Capture any error output

	err := cmd.Run()
	if err != nil {
		fmt.Printf("failed to encrypt file: %v\n, output %s", err, out.String())
		return err
	}

	// Write the encrypted output to the file at outputPath
	err = os.WriteFile(path+variableName+".yaml", out.Bytes(), 0644)
	if err != nil {
		fmt.Printf("failed to write encrypted data to file: %v\n", err)
		return err
	}

	return nil
}

// decryptAnsibleVaultFile uses ansible-vault to decrypt a file and returns its content.
func DecryptAnsibleVaultFile(encryptedString string, vaultPasswordFile string, env bool) (string, error) {

	tmpfile, err := os.CreateTemp("", "ansible-vault-*.yml")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up the file afterwards

	if _, err := tmpfile.Write([]byte(encryptedString)); err != nil {
		tmpfile.Close()
		return "", fmt.Errorf("writing to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		return "", fmt.Errorf("closing temp file: %v", err)
	}

	var cmd *exec.Cmd
	if env{
		cmd = exec.Command("ansible-vault", "view", tmpfile.Name())
	}else{
		cmd = exec.Command("ansible-vault", "view", tmpfile.Name(), "--vault-password-file", vaultPasswordFile)
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out // Capture any error output for diagnostics

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to decrypt file: %v, output %s", err, out.String())
	}

	return out.String(), nil
}