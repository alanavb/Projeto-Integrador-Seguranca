from flask import Blueprint, render_template, request, redirect, session
from datetime import timedelta
import time
import bcrypt
import pyotp
import qrcode
import io
import base64
import json
import secrets

from models.user_model import *
from services.validation_service import validar_email, validar_senha
from services.crypto_service import criptografar_dado, descriptografar_dado
from database.connection import get_db

auth = Blueprint("auth", __name__)

###############################################################################
## REQUISITO 1 - LOGIN E AUTENTICAÇÃO PRIMÁRIA
###############################################################################
@auth.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        senha = request.form.get("senha") or ""

        if not email:
            return render_template("login.html", erro="Email inválido")

        usuario = get_user_by_email(email)

        if not usuario:
            return render_template("login.html", erro="Usuário ou senha inválidos")

        ###############################################################################
        ## REQUISITO 1.11 - PROTEÇÃO CONTRA FORÇA BRUTA
        ###############################################################################
        bloqueado_ate = usuario[3]
        if bloqueado_ate and bloqueado_ate > time.time():
            return render_template("login.html", erro="Conta bloqueada temporariamente.")

        ###############################################################################
        ## REQUISITO 1.1 - HASH SEGURO (BCRYPT)
        ###############################################################################
        stored_hash = usuario[1].encode() if isinstance(usuario[1], str) else usuario[1]

        if not bcrypt.checkpw(senha.encode(), stored_hash):
            tentativas = (usuario[6] or 0) + 1

            if tentativas >= 5:
                bloquear_usuario(email, time.time() + 300)
            else:
                update_tentativas(email, tentativas)

            print(f"[AUDITORIA] Falha de login: {email}")
            return render_template("login.html", erro="Usuário ou senha inválidos")

        limpar_bloqueio(email)

        session["email_temp"] = email

        if usuario[5] == 0: return redirect("/qr")
        else: return redirect("/2fa")

    return render_template("login.html", sucesso=session.pop("sucesso", None))


###############################################################################
## REQUISITO 1.1, 1.3 & 3.4 - CADASTRO
###############################################################################
@auth.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))

        usuario_existente = get_user_by_email(email)
        if usuario_existente: return render_template("register.html", erro="Este e-mail já está em uso. Tente outro.")
        
        senha = request.form.get("senha")
        confirmar = request.form.get("confirmar")

        if not email: return render_template("cadastro.html", erro="Email inválido")

        erro_senha = validar_senha(senha)
        if erro_senha: return render_template("cadastro.html", erro=erro_senha)

        if senha != confirmar: return render_template("cadastro.html", erro="Senhas não conferem")

        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
        chave_2fa = pyotp.random_base32()

        ###############################################################################
        ## REQUISITO 3.4 - CRIPTOGRAFIA EM REPOUSO
        ###############################################################################
        backup_codes = [secrets.token_hex(4) for _ in range(5)]
        backup_codes_cripto = criptografar_dado(json.dumps(backup_codes))

        try:
            create_user(email, senha_hash, chave_2fa, backup_codes_cripto)
            session["sucesso"] = "Cadastro realizado com sucesso!"
            return redirect("/")
        except:
            return render_template("cadastro.html", erro="E-mail já cadastrado.")

    return render_template("cadastro.html")


###############################################################################
## REQUISITO 1.5 - 2FA
###############################################################################
@auth.route("/2fa", methods=["GET", "POST"])
def twofa():
    email = session.get("email_temp")
    if not email: return redirect("/")

    resultado = get_2fa_data(email)
    if not resultado: return redirect("/")

    chave_2fa = resultado[0]

    ###############################################################################
    ## REQUISITO 3.4 - DESCRIPTOGRAFIA
    ###############################################################################
    backup_codes = json.loads(descriptografar_dado(resultado[1]))
    totp = pyotp.TOTP(chave_2fa)

    if request.method == "POST":
        codigo = request.form["codigo"]

        if codigo in backup_codes:
            backup_codes.remove(codigo)
            update_backup_codes(email, criptografar_dado(json.dumps(backup_codes)))
            session["user"] = email
            return redirect("/dashboard")

        if totp.verify(codigo):
            session["user"] = email
            print(f"[AUDITORIA] Login 2FA sucesso: {email}")
            return redirect("/dashboard")

        return render_template("2fa.html", erro="Código inválido")

    return render_template("2fa.html")


###############################################################################
## REQUISITO 2 - RECUPERAÇÃO DE SENHA
###############################################################################
@auth.route("/recuperacao", methods=["GET", "POST"])
def recuperacao():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))

        if email and get_user_by_email(email):
            token = secrets.token_urlsafe(32)
            expiracao = int(time.time()) + 3600
            update_reset_token(email, token, expiracao)

            print(f"[SEGURANÇA] Recuperação: http://localhost:5000/resetar?token={token}&email={email}")

        return render_template("recuperacao.html", sucesso="Instruções enviadas se o e-mail existir.")

    return render_template("recuperacao.html")


@auth.route("/resetar", methods=["GET", "POST"])
def resetar():
    email = request.args.get("email") or request.form.get("email")
    token_url = request.args.get("token") or request.form.get("token")

    if request.method == "POST":
        nova_senha = request.form.get("senha")
        dados = get_reset_data(email)

        if not dados or dados[0] != token_url or int(time.time()) > dados[1]:
            return render_template("resetar.html", erro="Token inválido ou expirado.", email=email, token=token_url)

        erro_senha = validar_senha(nova_senha)
        if erro_senha:
            return render_template("resetar.html", erro=erro_senha, email=email, token=token_url)

        senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt())
        update_password(email, senha_hash)

        print(f"[AUDITORIA] Senha redefinida para {email}")
        return render_template("login.html", sucesso="Senha redefinida com sucesso!")

    return render_template("resetar.html", email=email, token=token_url)


###############################################################################
## LOGOUT
###############################################################################
@auth.route("/logout")
def logout():
    session.clear()
    response = redirect("/")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


###############################################################################
## DASHBOARD
###############################################################################
@auth.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect("/")
    return render_template("dashboard.html", email=session["user"])


###############################################################################
## QR CODE
###############################################################################
@auth.route("/qr")
def qr():
    if "email_temp" not in session: return redirect("/")

    email = session["email_temp"]
    res = get_chave_2fa(email)

    totp = pyotp.TOTP(res[0])
    uri = totp.provisioning_uri(name=email, issuer_name="Sistema_Seguro")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    return render_template("qr.html", qr_code=base64.b64encode(buf.getvalue()).decode())


@auth.route("/qr-confirm", methods=["POST"])
def qr_confirm():
    email = session.get("email_temp")
    ativar_2fa(email)
    return redirect("/2fa")
