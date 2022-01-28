KSK=Keys/K.+008+21544
ZSK=Keys/K.+008+17913
ORIGIN=.
XFER_SOURCE=d.root-servers.net
READZONE=ldns-read-zone
ZONEHASH=env LD_LIBRARY_PATH=/usr/local/lib ${HOME}/Edit/ldns-zone-digest/ldns-zone-digest

root.zone.hashed: root.zone.signed
	${ZONEHASH} -c -z ${ZSK}.private -g -o $@__ ${ORIGIN} root.zone.signed
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

root.zone.signed: root.zone.placeholder
	ldns-signzone -f $@__ root.zone.placeholder ${KSK} ${ZSK}
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

root.zone.placeholder: root.zone.unsigned
	${ZONEHASH} -p 1:1 -g -o $@__ ${ORIGIN} root.zone.unsigned
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

root.zone.unsigned:
	dig @${XFER_SOURCE} ${ORIGIN} AXFR > $@_
	${READZONE} -s $@_ \
	| awk '$$4 != "DNSKEY"' \
	> $@
	rm -fv $@_

clean:
	rm -fv root.zone.*
