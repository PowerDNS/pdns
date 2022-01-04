FROM debian:bullseye

EXPOSE 749 88

ENV DEBIAN_FRONTEND noninteractive
# The -qq implies --yes
RUN apt-get -qq update
RUN apt-get -qq install locales krb5-kdc krb5-admin-server
RUN apt-get -qq clean

#RUN locale-gen "en_US.UTF-8"
#RUN echo "LC_ALL=\"en_US.UTF-8\"" >> /etc/default/locale

ENV REALM ${REALM:-EXAMPLE.COM}
ENV SUPPORTED_ENCRYPTION_TYPES ${SUPPORTED_ENCRYPTION_TYPES:-aes256-cts-hmac-sha1-96:normal}
ENV KADMIN_PRINCIPAL ${KADMIN_PRINCIPAL:-kadmin/admin}
ENV KADMIN_PASSWORD ${KADMIN_PASSWORD:-MITiys4K5}

COPY kerberos-init.sh /tmp/
CMD /tmp/kerberos-init.sh
