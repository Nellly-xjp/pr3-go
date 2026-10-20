
Write-Host "=== Генерація PKI інфраструктури для mTLS ===" -ForegroundColor Green

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=MyRootCA"

$configContent = @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@
$configContent | Out-File -Encoding ascii server_ext.cnf

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -config server_ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile server_ext.cnf -extensions v3_req

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=dispatcher-agent-01"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

Remove-Item server.csr, client.csr, server_ext.cnf, ca.srl -ErrorAction SilentlyContinue

Write-Host "=== Генерацію сертифікатів успішно завершено! ===" -ForegroundColor Green