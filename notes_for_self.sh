openssl req -new -nodes -out service.csr -newkey rsa:2048 -keyout service.key -config service.conf


openssl x509 -req -in service.csr \
-CA ~/.mitmproxy/mitmproxy-ca.pem \
-CAkey ~/.mitmproxy/mitmproxy-ca.pem \
-CAcreateserial -out service.crt \
-days 3650 -sha256 -extfile service.conf -extensions v3_req


# reverse proxy symb-links
ln -s /etc/nginx/sites-available/reverse-proxy.conf /etc/nginx/sites-enabled/


# firewall enable
ufw allow 54322/tcp


# start script locations:
# /etc/systemd/system/mitmdump.service
# /etc/systemd/system/loki.service
# /etc/systemd/system/loki.service
