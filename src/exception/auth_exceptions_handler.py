from fastapi import Request, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from src.schemas.common.service_response import create_response
from src.exception.auth_exceptions import (
    UnauthorizedException,
    UserAlreadyExistsException,
    NotFoundException,
)

def register_exception_handlers(app: FastAPI):
    """Register global exception handlers for custom exceptions."""

    async def handler(exc: Exception, status_code: int, message: str, error: str):
        response = create_response(
            data=None,
            message=message,
            is_error=True,
            errors=error
        )

        return JSONResponse(
            status_code=status_code,
            content=jsonable_encoder(response, exclude_none=True),
        )
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            return await handler(exc, exc.status_code, "Authentication required", exc.detail)
        return await handler(exc, exc.status_code, "Unauthorized", exc.detail)

    @app.exception_handler(UnauthorizedException)
    async def unauthorized_exception_handler(request: Request, exc: UnauthorizedException):
        return await handler(exc, exc.status_code, "Unauthorized", exc.detail)

    @app.exception_handler(UserAlreadyExistsException)
    async def user_exists_exception_handler(request: Request, exc: UserAlreadyExistsException):
        return await handler(exc, exc.status_code, "Validation Failed", exc.detail)

    @app.exception_handler(NotFoundException)
    async def not_found_exception_handler(request: Request, exc: NotFoundException):
        return await handler(exc, exc.status_code, "Not Found", exc.detail)
    
    

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request, exc):
        errors = {} 

        for err in exc.errors():
            loc = list(err["loc"])
            if loc == ["body"]:
                return await handler(exc, 400, "Validation Failed", err["msg"])
            if loc and loc[0] == "body":
                loc = loc[1:]

            field = ".".join(map(str, loc))
            errors[field] = err["msg"] 

        return await handler(exc, 400, "Validation Failed", errors)

       

    