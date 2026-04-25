from mitmproxy import dns
from cached_public_ip import get_public_ip, ip_to_bytes

def dns_request(flow: dns.DNSFlow):
    request = flow.request

    if not request.questions:
        return

    q = request.questions[0]

    if q.name.rstrip('.') == "gaamsihei.io" and q.type == dns.types.A:
        flow.response = dns.DNSMessage(
            id=request.id,
            query=False,

            op_code=request.op_code,
            authoritative_answer=True,
            truncation=False,
            recursion_desired=request.recursion_desired,
            recursion_available=True,
            reserved=0,
            response_code=dns.response_codes.NOERROR,

            questions=request.questions,

            answers=[
                dns.ResourceRecord(
                    name=q.name,
                    type=dns.types.A,
                    class_=dns.classes.IN,
                    ttl=60,
                    # IP in hex
                    data=ip_to_bytes(get_public_ip()),
                )
            ],

            authorities=[],
            additionals=[],
        )
