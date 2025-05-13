import uvicorn

from fastapi import FastAPI, status
from fastapi.responses import RedirectResponse

#from routers import user

from api.routers import users


docs_url = "/docs"

app = FastAPI(
	title="ENEO filed service",
	description ="Application to manager ENEO filed service",
	version="1",
	docs_url=docs_url
)

#app.include_router(user.router)

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


app.include_router(
	prefix='/api/v1',
	router=users.router
)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
