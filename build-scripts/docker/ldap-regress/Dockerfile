ARG VERSION
FROM osixia/openldap:$VERSION
ADD bootstrap /container/service/slapd/assets/config/bootstrap
RUN rm -rf /container/service/slapd/assets/config/bootstrap/schema/mmc
RUN mkdir -p /var/lib/ldap-powerdns
RUN chown openldap:openldap /var/lib/ldap-powerdns
