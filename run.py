from app.app import app
from app.api.v1.base_api import base_api
from app.core.config.corely_settings import CorelySettings
from app.core.auth.endpoints import auth as authAPI
from app.api.v1.user_api import users as userAPI
from app.api.v1.customer_api import customer as customerAPI
from app.api.v1.store_api import store as storeAPI
from app.api.v1.product_api import product as productAPI
from app.api.v1.pos_api import pos as posAPI

""""""
settings = CorelySettings()
api_version = settings.api_version

"""
Here APIS will be defined
"""


app.include_router(authAPI, prefix=f"/api/{api_version}/auth", tags=["Authentication"])
app.include_router(base_api, prefix=f"/base/api/{api_version}", tags=["Base api"])
app.include_router(userAPI, prefix=f"/api/{api_version}/user", tags=["User API's"])
app.include_router(
    customerAPI, prefix=f"/api/{api_version}/customer", tags=["Customer API's"]
)
app.include_router(storeAPI, prefix=f"/api/{api_version}/store", tags=["Store API's"])
app.include_router(
    productAPI, prefix=f"/api/{api_version}/product", tags=["Product API's"]
)
app.include_router(posAPI, prefix=f"/api/{api_version}/pos", tags=["Pos API's"])
