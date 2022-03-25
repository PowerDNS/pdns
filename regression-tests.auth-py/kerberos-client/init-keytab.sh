echo commands to run:
echo Passwords entered should match those in the kerberos-server setup script
echo rm -f kt.keytab
echo ktutil
echo add_entry -password -p testuser1@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
echo add_entry -password -p testuser2@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
echo add_entry -password -p DNS/ns1.example.net@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
echo wkt kt.keytab
echo quit
