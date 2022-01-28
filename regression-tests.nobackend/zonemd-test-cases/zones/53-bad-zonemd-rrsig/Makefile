ORIGIN=zonemd.packet-pushers.com
READZONE=/usr/local-latest/bin/ldns-read-zone
ZONEHASH=env LD_LIBRARY_PATH=/usr/local/lib ${HOME}/Edit/ldns-zone-digest/ldns-zone-digest
AUTH_NS=$(shell dig +short ${ORIGIN} NS | head -n 1)

${ORIGIN}.badsig: ${ORIGIN}.clean
	cat ${ORIGIN}.clean \
	| awk '$$4 == "RRSIG" && $$5 == "ZONEMD" {gsub("[0-9]","1",$$13);} {print}' \
	> $@_
	mv $@_ $@


${ORIGIN}.clean: ${ORIGIN}.queries
	${READZONE} ${ORIGIN}.queries \
	> $@_
	${ZONEHASH} -v ${ORIGIN} $@_
	mv $@_ $@

${ORIGIN}.queries:
	cp /dev/null $@_
	dig @${AUTH_NS} +dnssec ${ORIGIN} SOA >> $@_
	dig @${AUTH_NS} +dnssec ${ORIGIN} NS >> $@_
	dig @${AUTH_NS} +dnssec ${ORIGIN} TXT >> $@_
	dig @${AUTH_NS} +dnssec ${ORIGIN} ZONEMD >> $@_
	dig @${AUTH_NS} +dnssec ${ORIGIN} DNSKEY >> $@_
	dig @${AUTH_NS} +dnssec ${ORIGIN} NSEC >> $@_
	dig @${AUTH_NS} +dnssec localhost.${ORIGIN} A >> $@_
	dig @${AUTH_NS} +dnssec localhost.${ORIGIN} NSEC >> $@_
	mv $@_ $@

clean:
	rm -v ${ORIGIN}.queries
	rm -v ${ORIGIN}
