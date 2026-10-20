package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	fmt.Println("=== Генерація PKI сертифікатів на Go ===")

	// 1. Створення Root CA
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "MyRootCA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	savePEM("ca.crt", "CERTIFICATE", caBytes)
	savePEM("ca.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caPrivKey))

	// 2. Сертифікат сервера (SAN: localhost, 127.0.0.1)
	serverPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverBytes, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverPrivKey.PublicKey, caPrivKey)
	savePEM("server.crt", "CERTIFICATE", serverBytes)
	savePEM("server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverPrivKey))

	// 3. Сертифікат клієнта (CN: dispatcher-agent-01)
	clientPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "dispatcher-agent-01",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	clientBytes, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientPrivKey.PublicKey, caPrivKey)
	savePEM("client.crt", "CERTIFICATE", clientBytes)
	savePEM("client.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientPrivKey))

	fmt.Println("Успішно згенеровано: ca.crt, ca.key, server.crt, server.key, client.crt, client.key")
}

func savePEM(filename, blockType string, bytes []byte) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	pem.Encode(file, &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
}