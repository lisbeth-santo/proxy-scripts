from mitmproxy import dns
from cached_public_ip import get_public_ip
import mitmproxy.http

class DNSModifier:
    def dns_request(self, flow: dns.DNSFlow):
        if flow.request.questions[0].name == "gaamsihei.io":
            flow.response = dns.Message.make_response(
                flow.request,
                answers=[
                    dns.ResourceRecord(
                        name="gaamsihei.io",
                        type=dns.Type.A,
                        class_=dns.Class.IN,
                        ttl=604800,
                        data=get_public_ip()
                    )
                ]
            )

addons = [DNSModifier()]
