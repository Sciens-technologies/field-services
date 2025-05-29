import uvicorn
from fastapi import FastAPI, status, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.exceptions import ResponseValidationError, RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import traceback
from fastapi.security import OAuth2PasswordRequestForm

from api.routers.users import users_router
from api.routers.admin import admin_router

docs_url = "/docs"

app = FastAPI(
    title="ENEO field service",
    description="Application to manage ENEO field service",
    version="1",
    docs_url=docs_url
)

app.include_router(users_router, prefix="/api/v1/users", tags=["user"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])  # For admin endpoints

# Note: There is no /api/v1/users/token endpoint. Use /api/v1/users/login/ for authentication.

@app.exception_handler(ResponseValidationError)
async def validation_exception_handler(request: Request, exc: ResponseValidationError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error: Response validation failed",
            "errors": str(exc.errors())
        }
    )

@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Request validation error",
            "errors": exc.errors()
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    print(f"Unhandled exception: {str(exc)}")
    print(traceback.format_exc())
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc)
        }
    )

@app.get('/', include_in_schema=False)
async def redirect_to_docs():
    """Redirect to docs"""
    return RedirectResponse(url='/docs')

@app.get('/ping', include_in_schema=True, status_code=status.HTTP_200_OK)
async def health():
    """Returns API health"""
    return {'status': 'ok', 'ping': 'pong'}

@app.post("/api/v1/login/", include_in_schema=False)
async def login_alias(request: Request):
    form = await request.form()
    # Extract username and password from form
    username = form.get("username")
    password = form.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    # Create a fake OAuth2PasswordRequestForm
    class FakeOAuth2PasswordRequestForm:
        def __init__(self, username, password):
            self.username = username
            self.password = password
            self.scopes = []
            self.client_id = None
            self.client_secret = None
    form_data = FakeOAuth2PasswordRequestForm(username, password)
    # Get DB session
    from api.routers.users import login_user, get_db
    db = next(get_db())
    return await login_user(form_data=form_data, db=db)

# Optional: Uncomment to run with `python main.py`
# if __name__ == "__main__":
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
