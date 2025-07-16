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
