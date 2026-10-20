package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

func main() {
	fmt.Println("=== [КЛІЄНТ] Запуск mTLS Диспетчера ===")

	// 1. Завантаження клієнтського сертифіката та ключа (згенерувати їх потрібно в папку certs/)
	clientCert, err := tls.LoadX509KeyPair("certs/client.crt", "certs/client.key")
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося завантажити сертифікат клієнта: %v", err)
	}

	// 2. Завантаження Root CA для перевірки сертифіката сервера
	caCertPEM, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося прочитати certs/ca.crt: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatal("[ПОМИЛКА] Не вдалося додати Root CA у пул сертифікатів")
	}

	// 3. Конфігурація TLS для клієнта
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert}, // Сертифікат клієнта для mTLS
		RootCAs:      caCertPool,                    // Довірений Root CA
		ServerName:   "localhost",                   // SAN перевірка адреси сервера
		MinVersion:   tls.VersionTLS12,
	}

	// 4. Підключення до mTLS сервера на порту :8443
	conn, err := tls.Dial("tcp", "127.0.0.1:8443", tlsConfig)
	if err != nil {
		log.Fatalf("[ПОМИЛКА ПІДКЛЮЧЕННЯ] %v", err)
	}
	defer conn.Close()

	fmt.Println("[КЛІЄНТ] Взаємне mTLS з'єднання успішно встановлено!")

	// 5. Відправка повідомлення про інцидент (обов'язково з символом переносу \n в кінці)
	alertMessage := "CRITICAL_ERROR: Database connection timeout on node-04\n"
	_, err = conn.Write([]byte(alertMessage))
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Помилка відправки даних: %v", err)
	}

	// 6. Отримання відповіді-підтвердження від сервера
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("[ПОМИЛКА] Не вдалося отримати відповідь від сервера: %v", err)
		return
	}

	fmt.Printf("[ВІДПОВІДЬ СЕРВЕРА]: %s", response)
}
