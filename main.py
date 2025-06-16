from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from api.routers.users import users_router
from api.routers.admin import admin_router
from api.routers.device import device_router
from db.database import engine, Base
from fastapi.openapi.utils import get_openapi

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
	title="Field Services API",
	description="API for Field Services Management System",
	version="1.0.0"
)

# Configure CORS
app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],  # In production, replace with specific origins
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

# Mount routers
app.include_router(users_router, prefix="/api/v1", tags=["users"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(device_router, prefix="/api/v1/device", tags=["device"])

@app.get("/")
async def root():
	return {"message": "Welcome to Field Services API"}

# Remove OAuth2PasswordBearer from OpenAPI security schemes for login
def custom_openapi():
	if app.openapi_schema:
		return app.openapi_schema
	openapi_schema = get_openapi(
		title=app.title,
		version=app.version,
		description=app.description,
		routes=app.routes,
	)
	# Replace OAuth2PasswordBearer with HTTP Bearer in securitySchemes
	openapi_schema["components"]["securitySchemes"] = {
		"BearerAuth": {
			"type": "http",
			"scheme": "bearer",
			"bearerFormat": "JWT"
		}
	}
	# Set BearerAuth as the default security for all endpoints except /login
	for path, methods in openapi_schema["paths"].items():
		for method in methods:
			if path == "/api/v1/login":
				if "security" in openapi_schema["paths"][path][method]:
					del openapi_schema["paths"][path][method]["security"]
			else:
				openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]
	app.openapi_schema = openapi_schema
	return app.openapi_schema

app.openapi = custom_openapi