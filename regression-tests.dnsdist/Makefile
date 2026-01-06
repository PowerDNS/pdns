clean-certs:
	rm -f ca.key ca.pem ca.srl server.csr server.key server.pem server.chain server.ocsp
clean-configs:
	rm -rf configs/*
certs:
	# Generate a new CA
	openssl req -new -x509 -days 1 -extensions v3_ca -keyout ca.key -out ca.pem -nodes -config configCA.conf
	# Generate a new server certificate request
	openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -config configServer.conf
	# Sign the server cert
	openssl x509 -req -days 1 -CA ca.pem -CAkey ca.key -CAcreateserial -in server.csr -out server.pem -extfile configServer.conf -extensions v3_req
	# Generate a chain
	cat server.pem ca.pem > server.chain
	# Generate a password-protected PKCS12 file
	openssl pkcs12 -export -passout pass:passw0rd -clcerts -in server.pem -CAfile ca.pem -inkey server.key -out server.p12
	# Generate a second server certificate request
	openssl req -new -newkey rsa:2048 -nodes -keyout server2.key -out server2.csr -config configServer2.conf
	# Sign the server cert
	openssl x509 -req -days 1 -CA ca.pem -CAkey ca.key -CAcreateserial -in server2.csr -out server2.pem -extfile configServer2.conf -extensions v3_req
	# Generate a chain
	cat server2.pem ca.pem > server2.chain
	# Generate a ECDSA key with P-256
	openssl ecparam -name secp256r1 -genkey -noout -out server-ec.key
	# Generate a new server certificate request with the ECDSA key
	openssl req -new -key server-ec.key -nodes -out server-ec.csr -config configServer.conf
	# Sign the server cert
	openssl x509 -req -days 1 -CA ca.pem -CAkey ca.key -CAcreateserial -in server-ec.csr -out server-ec.pem -extfile configServer.conf -extensions v3_req
	# Generate a chain
	cat server-ec.pem ca.pem > server-ec.chain
	# Generate a new server certificate request (IP-only)
	openssl req -new -newkey rsa:2048 -nodes -keyout server-ip-only.key -out server-ip-only.csr -config configServer-ip-only.conf
	# Sign the server cert
	openssl x509 -req -days 1 -CA ca.pem -CAkey ca.key -CAcreateserial -in server-ip-only.csr -out server-ip-only.pem -extfile configServer-ip-only.conf -extensions v3_req
	# Generate a chain
	cat server-ip-only.pem ca.pem > server-ip-only.chain
