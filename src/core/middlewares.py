# src/auth/middlewares.py
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from uuid import uuid4
from src.core.tracing import request_id_var, client_ip_var
from src.config.logger import Logger
import secrets
import string

log = Logger().get_logger()

def generate_id(length: int = 12) -> str:
    if length < 3:
        raise ValueError("Length must be at least 3 for uppercase, lowercase, and digit")
    
    result = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits)
    ]
    
    alphabet = string.ascii_letters + string.digits
    result += [secrets.choice(alphabet) for _ in range(length - 3)]
    secrets.SystemRandom().shuffle(result)
    return ''.join(result)


class RequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        #Request ID
        request_id = request.headers.get("X-Request-ID", generate_id())
        token = request_id_var.set(request_id)

        #Client IP
        client_ip = request.client.host if request.client else "N/A"
        client_ip_token = client_ip_var.set(client_ip)
        try:
            log.info(f"Incoming request: {request.method} {request.url.path}")
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_var.reset(token)
            client_ip_var.reset(client_ip_token)