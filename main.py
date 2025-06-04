import uvicorn
from fastapi import FastAPI, status, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.exceptions import ResponseValidationError, RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import traceback

from api.routers.users import users_router
from api.routers.admin import admin_router
from dotenv import load_dotenv
import os
load_dotenv()
docs_url = "/docs"

app = FastAPI(
	title="ENEO filed service",
	description ="Application to manager ENEO filed service",
	version="1",
	docs_url=docs_url
)

app.include_router(users_router, prefix="/api/v1", tags=["user"])
app.include_router(admin_router, prefix="/api/v1/admin",tags=["admin"])  # For admin endpoints


# Add custom exception handler for ResponseValidationError
@app.exception_handler(ResponseValidationError)
async def validation_exception_handler(request: Request, exc: ResponseValidationError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error: Response validation failed",
            "errors": str(exc.errors())
        }
    )

# Add handler for RequestValidationError
@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Request validation error",
            "errors": exc.errors()
        }
    )

# Add handler for HTTPException
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)}
    )

# Add handler for general exceptions
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Log the error with traceback for debugging
    print(f"Unhandled exception: {str(exc)}")
    print(traceback.format_exc())
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            # Only include error details in development, remove in production
            "error": str(exc)
        }
    )

@app.get('/', include_in_schema=False)
async def redirect_to_docs():
    """
    redirect to docs
    """
    return RedirectResponse(url='/docs')


@app.get('/ping', include_in_schema=True, status_code=status.HTTP_200_OK)
async def health():
    """
    Returns API health 
    """
    return {'status': 'ok', 'ping':'pong'}
