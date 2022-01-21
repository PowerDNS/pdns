KSK=Keys/Karpa.+008+18949
ZSK=Keys/Karpa.+008+29094
ORIGIN=arpa
XFER_SOURCE=xfr.lax.dns.icann.org
READZONE=ldns-read-zone
ZONEHASH=env LD_LIBRARY_PATH=/usr/local/lib ${HOME}/Edit/ldns-zone-digest/ldns-zone-digest

arpa.zone.hashed: arpa.zone.signed
	${ZONEHASH} -c -z ${ZSK}.private -g -o $@__ ${ORIGIN} arpa.zone.signed
	${READZONE} $@__ \
	| awk '$$4 == "RRSIG" {$$12=toupper($$12)} {print}' \
	> $@_
	mv $@_ $@
	rm -fv $@__

arpa.zone.signed: arpa.zone.placeholder
	ldns-signzone -f $@__ arpa.zone.placeholder ${KSK} ${ZSK}
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

arpa.zone.placeholder: arpa.zone.unsigned
	${ZONEHASH} -p 1:1 -g -o $@__ ${ORIGIN} arpa.zone.unsigned
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

arpa.zone.unsigned:
	dig @${XFER_SOURCE} ${ORIGIN} AXFR > $@_
	${READZONE} -s $@_ \
	| awk '$$4 != "DNSKEY"' \
	> $@
	rm -fv $@_

clean:
	rm -fv arpa.zone.*
