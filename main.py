from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from api.routers.users import users_router
from api.routers.admin import admin_router
from api.routers.work_order import router as work_orders_router
from api.routers.device import device_router
from db.database import engine, Base
# from fastapi.openapi.utils import get_openapi
from fastapi.responses import RedirectResponse
# Create database tables
#Base.metadata.create_all(bind=engine)

docs_url = "/docs"
 
app = FastAPI(
	title="ENEO filed service",
	description ="Application to manager ENEO filed service",
	version="1",
	docs_url='/docs',
	#redoc_url=None,
	openapi_url="/openapi.json"
)
 
# # Configure CORS
# app.add_middleware(
# 	CORSMiddleware,
# 	allow_origins=["*"],  # In production, replace with specific origins
# 	allow_credentials=True,
# 	allow_methods=["*"],
# 	allow_headers=["*"],
# )

# Mount routers
app.include_router(users_router, prefix="/api/v1", tags=["users"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(work_orders_router, prefix="/api/v1", tags=["work-orders"])
app.include_router(device_router, prefix="/api/v1/device", tags=["device"])

@app.get('/ping', include_in_schema=True, status_code=status.HTTP_200_OK)
async def health():
    """
    Returns API health 
    """
    return {'status': 'ok', 'ping':'pong'}
# # Remove OAuth2PasswordBearer from OpenAPI security schemes for login
# def custom_openapi():
# 	if app.openapi_schema:
# 		return app.openapi_schema
# 	openapi_schema = get_openapi(
# 		title=app.title,
# 		version=app.version,
# 		description=app.description,
# 		routes=app.routes,
# 	)
# 	# Replace OAuth2PasswordBearer with HTTP Bearer in securitySchemes
# 	openapi_schema["components"]["securitySchemes"] = {
# 		"BearerAuth": {
# 			"type": "http",
# 			"scheme": "bearer",
# 			"bearerFormat": "JWT"
# 		}
# 	}
# 	# Set BearerAuth as the default security for all endpoints except /login
# 	for path, methods in openapi_schema["paths"].items():
# 		for method in methods:
# 			if path == "/api/v1/login":
# 				if "security" in openapi_schema["paths"][path][method]:
# 					del openapi_schema["paths"][path][method]["security"]
# 			else:
# 				openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]
# 	app.openapi_schema = openapi_schema
# 	return app.openapi_schema

# app.openapi = custom_openapi
