# src/auth/tracing.py
import contextvars
import httpx
import logging

# Request ID context variable
request_id_var = contextvars.ContextVar("request_id", default="N/A")

# Async HTTP client for downstream calls
class TracedClient(httpx.AsyncClient):
    async def request(self, method, url, **kwargs):
        headers = kwargs.get("headers", {})
        headers["X-Request-ID"] = request_id_var.get()
        kwargs["headers"] = headers
        return await super().request(method, url, **kwargs)

# Logging filter to inject request ID
class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True
