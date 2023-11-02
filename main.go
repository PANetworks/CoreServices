package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	socks5 "github.com/armon/go-socks5"
)

const (
	defaultUser  = "ubuntu"
)

func decryptPrivateKey(encryptedPrivateKeyPEM, password string) (string, error) {
	block, _ := pem.Decode([]byte(encryptedPrivateKeyPEM))
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing the encrypted key")
	}

	decryptedPrivateKeyBytes, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return "", err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivateKeyBytes)
	if err != nil {
		return "", err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

func main() {

	encryptedPrivateKeyPEM := `-----BEGIN ENCRYPTED PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1a2b0d44ecdb984d46dd8ea62f3503c7

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
-----END ENCRYPTED PRIVATE KEY-----`

	if len(os.Args) < 4 {
		log.Fatalln("Usage: program password serverAddress localAddress")
	}
	password := os.Args[1]
	serverAddress := os.Args[2]
	localAddress := os.Args[3]
	
	decryptedKey, err := decryptPrivateKey(encryptedPrivateKeyPEM, password)
	if err != nil {
		log.Fatalf("Error decrypting private key: %v", err)
	}

	if err := startSocks5Server(decryptedKey, serverAddress, localAddress); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func startSocks5Server(decryptedKey, serverAddress, localAddress string) error {
	signer, err := ssh.ParsePrivateKey([]byte(decryptedKey))
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: defaultUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	connection, err := ssh.Dial("tcp", serverAddress, config)
	if err != nil {
		return err
	}

	serverSocks5, err := socks5.New(&socks5.Config{})
	if err != nil {
		return err
	}

	listener, err := connection.Listen("tcp", localAddress)
	if err != nil {
		return err
	}

	return acceptAndHandleConnections(listener, serverSocks5)
}

func acceptAndHandleConnections(listener net.Listener, serverSocks5 *socks5.Server) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go serverSocks5.ServeConn(conn)
	}
}
