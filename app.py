from flask import Flask, request, redirect, session
from datetime import timedelta
from dotenv import load_dotenv
import os

# IMPORT DO CONTROLLER
from controllers.auth_controller import auth

###############################################################################
## CARREGAR VARIÁVEIS DE AMBIENTE
###############################################################################
load_dotenv()

app = Flask(__name__)

###############################################################################
## REQUISITO 3.6 - CHAVES CRIPTOGRÁFICAS PROTEGIDAS (SECRET_KEY)
###############################################################################
app.secret_key = os.getenv("SECRET_KEY", "supersecret")

###############################################################################
## REQUISITO 3.1 - FORÇAR HTTPS
###############################################################################
@app.before_request
def forcar_https():
    if not request.is_secure and app.env != "development":
        url_segura = request.url.replace("http://", "https://", 1)
        return redirect(url_segura, code=301)

###############################################################################
## REQUISITO 1.9 - SESSÕES COM TEMPO DE EXPIRAÇÃO
## REQUISITO 3.1 & 3.2 - COOKIES SEGUROS
###############################################################################
app.permanent_session_lifetime = timedelta(minutes=30)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

@app.before_request
def make_session_permanent():
    session.permanent = True

###############################################################################
## REGISTRO DO CONTROLLER (MVC)
###############################################################################
app.register_blueprint(auth)

###############################################################################
## INICIALIZAÇÃO
###############################################################################
if __name__ == "__main__":
    # REQUISITO 3.1 - HTTPS (CERTIFICADO TEMPORÁRIO)
    app.run(debug=True, ssl_context='adhoc')