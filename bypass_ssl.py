from mitmproxy import ctx, tls

def tls_clienthello(data: tls.ClientHelloData):
    server_name = data.client_hello.sni or "no-sni"

    target_hosts = ["gaamsihei.io"]

    if server_name in target_hosts:
        data.context.options.ssl_insecure = True
