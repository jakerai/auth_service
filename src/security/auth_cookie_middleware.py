from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.datastructures import MutableHeaders
from src.config.logger import Logger

log = Logger().get_logger()

class AuthCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = None
        if "authorization" not in request.headers:
            if request.url.path == "/users/profile":
                token = request.cookies.get("access_token")
            elif request.url.path == "/auth/refresh":
                token = request.cookies.get("refresh_token")

        if token:
            log.info("[AuthCookieMiddleware] Setting Authorization header from cookie")
            
            # ASGI headers are a list of (byte-key, byte-value) tuples
            new_header = (b"authorization", f"Bearer {token}".encode("latin-1"))
            
            # Getting existing headers from scope
            scope_headers = list(request.scope.get("headers", []))
            scope_headers.append(new_header)
            
            # Update the scope directly
            request.scope["headers"] = scope_headers

        response = await call_next(request)
        return response