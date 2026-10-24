import json
import requests
from os import environ as env
from urllib.parse import urlparse

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import LogoutOptions, StartInteractiveLoginOptions, StateData, TransactionData
from auth0_server_python.store.abstract import AbstractDataStore
from dotenv import load_dotenv
from flask import Flask, after_this_request, redirect, request, render_template
from markupsafe import escape

load_dotenv()

app = Flask(__name__)

class CookieStore(AbstractDataStore):
    def __init__(self, secret, cookie_name, max_age, model):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.model = model

    async def set(self, identifier, state, **_):
        @after_this_request
        def apply(response):
            data = state.model_dump() if hasattr(state, "model_dump") else state
            response.set_cookie(
                self.cookie_name,
                self.encrypt(identifier, data),
                httponly=True,
                samesite="Lax",
                secure=not env.get("APP_BASE_URL", "").startswith("http://"),
                max_age=self.max_age,
            )
            return response

    async def get(self, identifier, options=None):
        try:
            encrypted = options["request"].cookies.get(self.cookie_name)
            return self.model.model_validate(self.decrypt(identifier, encrypted)) if encrypted else None
        except Exception:
            app.logger.warning("Failed to decrypt cookie %s", self.cookie_name, exc_info=True)
            return None

    async def delete(self, *_, **__):
        @after_this_request
        def apply(response):
            response.delete_cookie(self.cookie_name)
            return response

def auth0():
    session_secret = env.get("AUTH0_SECRET")
    return ServerClient(
        domain=env.get("AUTH0_DOMAIN"),
        client_id=env.get("AUTH0_CLIENT_ID"),
        client_secret=env.get("AUTH0_CLIENT_SECRET"),
        redirect_uri=env.get("APP_BASE_URL") + "/callback",
        authorization_params={"scope": "openid profile email"},
        secret=session_secret,
        state_store=CookieStore(session_secret, "_a0_session", 259200, StateData), 
        transaction_store=CookieStore(session_secret, "_a0_tx", 300, TransactionData), 
    )

@app.route("/")
async def home():
    user = await auth0().get_user({"request": request})
    head = "<!DOCTYPE html><title>Perfil ITM - Auth0</title>"

    if user:
        # Extraer los datos si el usuario ya llenó el formulario
        user_metadata = user.get("user_metadata", {})
        return f"""
            {head}
            <body style="font-family: Arial; padding: 20px;">
                <h2 style="color: #004b87;">Bienvenido, {escape(user.get("email", ""))}</h2>
                <h3>Tus Datos Actuales:</h3>
                <ul>
                    <li><b>Tipo de Documento:</b> {escape(user_metadata.get("doc_type", "No registrado"))}</li>
                    <li><b>Número:</b> {escape(user_metadata.get("doc_number", "No registrado"))}</li>
                    <li><b>Dirección:</b> {escape(user_metadata.get("address", "No registrado"))}</li>
                    <li><b>Teléfono:</b> {escape(user_metadata.get("phone", "No registrado"))}</li>
                </ul>
                <a href="/dashboard" style="padding:10px; background:#004b87; color:white; text-decoration:none; border-radius:5px;">Actualizar Datos</a>
                <br><br>
                <a href="/logout" style="color:red;">Cerrar Sesión</a>
            </body>
        """

    return f"""
        {head}
        <body style="font-family: Arial; padding: 50px; text-align: center;">
            <h2 style="color: #004b87;">Proyecto ITM - Actividad 3</h2>
            <a href="/login" style="padding:10px 20px; background:#004b87; color:white; text-decoration:none; border-radius:5px;">Iniciar Sesión</a>
        </body>
    """

@app.route("/dashboard")
async def dashboard():
    user = await auth0().get_user({"request": request})
    if not user:
        return redirect("/login")
    
    # Renderiza tu archivo dashboard.html
    return render_template("dashboard.html")

@app.route("/update_profile", methods=["POST"])
async def update_profile():
    user = await auth0().get_user({"request": request})
    if not user:
        return redirect("/login")

    # 1. Recibir los datos del formulario HTML
    doc_type = request.form.get("doc_type")
    doc_number = request.form.get("doc_number")
    address = request.form.get("address")
    phone = request.form.get("phone")

    domain = env.get("AUTH0_DOMAIN")
    client_id = env.get("AUTH0_CLIENT_ID")
    client_secret = env.get("AUTH0_CLIENT_SECRET")
    user_id = user.get("sub")

    # 2. Solicitar el Token de la Management API de Auth0
    token_url = f"https://{domain}/oauth/token"
    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": f"https://{domain}/api/v2/",
        "grant_type": "client_credentials"
    }
    token_response = requests.post(token_url, json=token_payload)
    mgmt_token = token_response.json().get("access_token")

    # 3. Enviar el PATCH a Auth0 para actualizar los metadatos del usuario
    if mgmt_token:
        update_url = f"https://{domain}/api/v2/users/{user_id}"
        headers = {
            "Authorization": f"Bearer {mgmt_token}",
            "Content-Type": "application/json"
        }
        update_data = {
            "user_metadata": {
                "doc_type": doc_type,
                "doc_number": doc_number,
                "address": address,
                "phone": phone
            }
        }
        requests.patch(update_url, headers=headers, json=update_data)

    return redirect("/")

@app.route("/login")
async def login():
    url = await auth0().start_interactive_login(
        options=StartInteractiveLoginOptions(
            authorization_params=dict(request.args),
        ),
        store_options={"request": request},
    )
    return redirect(url)

@app.route("/callback")
async def callback():
    try:
        await auth0().complete_interactive_login(
            url=request.url, store_options={"request": request},
        )
        return redirect("/")
    except Exception:
        app.logger.exception("Callback error")
        return "Something went wrong. Check server logs for details.", 400

@app.route("/logout")
async def logout():
    url = await auth0().logout(
        options=LogoutOptions(return_to=env.get("APP_BASE_URL")),
        store_options={"request": request},
    )
    return redirect(url)

if __name__ == "__main__":
    url = urlparse(env.get("APP_BASE_URL"))
    app.run(host=url.hostname, port=url.port or 5000)