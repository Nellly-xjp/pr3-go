package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"pr3-go/email"
)

const (
	port       = ":8443"
	dutyEngine = "c.tyrkanych.korneliia@student.uzhnu.edu.ua"
)

func main() {
	fmt.Println("=== [СЕРВЕР] Запуск mTLS Secure Alert Gateway ===")

	serverCert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося завантажити сертифікати сервера: %v", err)
	}

	caCertPEM, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося прочитати certs/ca.crt: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatal("[ПОМИЛКА] Не вдалося додати Root CA у пул сертифікатів")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}


	// emailSvc := email.NewEmailService(
	// 	"smtp.ukr.net",
	// 	"465",
	// 	"ваша_пошта@ukr.net",         // <-- Вкажіть вашу пошту Ukr.net
	// 	"пароль_додатка_16_символів", // <-- Вкажіть генеруваний пароль додатка
	// )

	
	// Для Gmail (порт 587, STARTTLS):
	emailSvc := email.NewEmailService(
		"smtp.gmail.com",
		"587",
		"c.tyrkanych.korneliia@student.uzhnu.edu.ua",       // <-- Вкажіть вашого користувача Gmail
		"ctxt vbin mcyn ovps", // <-- App Password від Google
	)
	

	// 5. Відкриття захищеного mTLS TCP-сокета
	listener, err := tls.Listen("tcp", port, tlsConfig)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося відкрити mTLS слухача: %v", err)
	}
	defer listener.Close()

	fmt.Printf("[СЕРВЕР] mTLS Слухач успішно відкрито на порту %s\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ПОМИЛКА] Прийняття з'єднання: %v", err)
			continue
		}

		go handleClient(conn, emailSvc)
	}
}

func handleClient(conn net.Conn, emailSvc *email.EmailService) {
	defer conn.Close()

	// Примусове виконання mTLS-рукостискання
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("[ПОМИЛКА] З'єднання не є TLS")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[БЛОКУВАННЯ] Помилка TLS-рукостискання (неавторизований клієнт): %v", err)
		return
	}

	// Рівень 3. Аудит суб'єкта сертифіката (Zero Trust Identity)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Println("[ВІДХИЛЕНО] Клієнт не надав сертифікат")
		return
	}

	clientCert := state.PeerCertificates[0]
	clientCN := clientCert.Subject.CommonName
	certSerial := clientCert.SerialNumber.String()

	log.Printf("[Zero Trust Audit] Успішна автентифікація [CN=%s | Serial=%s]", clientCN, certSerial)

	// Читання повідомлення про інцидент від клієнта
	reader := bufio.NewReader(conn)
	incidentMsg, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		log.Printf("[ПОМИЛКА] Читання даних від %s: %v", clientCN, err)
		return
	}

	incidentMsg = strings.TrimSpace(incidentMsg)
	if incidentMsg == "" {
		return
	}

	log.Printf("[ІНЦИДЕНТ] Отримано від %s -> \"%s\"", clientCN, incidentMsg)

	// Відправка підтвердження клієнту
	fmt.Fprintln(conn, "[SERVER]: ALERT RECEIVED AND VERIFIED")

	// Рівні 2 та 3. Автоматична відправка MIME-листа на SMTP
	err = emailSvc.SendMIMEAlert(dutyEngine, incidentMsg, clientCN, certSerial)
	if err != nil {
		log.Printf("[ПОМИЛКА SMTP] Не вдалося надіслати email: %v", err)
	} else {
		log.Printf("[EMAIL] Сповіщення з файлом аудиту успішно надіслано інженеру (%s)", dutyEngine)
	}
}