from flask import Flask, render_template, request, redirect, session
from datetime import timedelta
import time
import bcrypt
import pyotp
import qrcode
import io
import base64
import mysql.connector
from dotenv import load_dotenv
import os
import json
import secrets
import re
from email_validator import validate_email, EmailNotValidError

###############################################################################
## REQUISITO 3.5 - USO DE ALGORITMO CRIPTOGRÁFICO 
###############################################################################
from cryptography.fernet import Fernet

load_dotenv()

app = Flask(__name__)
@app.before_request
def forcar_https():
    if not request.is_secure and app.env != "development":
        url_segura = request.url.replace("http://", "https://", 1)
        return redirect(url_segura, code=301)

###############################################################################
## REQUISITO 3.6 - CHAVES CRIPTOGRÁFICAS PROTEGIDAS (SECRET_KEY E ENCRYPTION_KEY)
###############################################################################
app.secret_key = os.getenv("SECRET_KEY", "supersecret")

# Configuração da chave AES para Requisito 3.4 (Criptografia em Repouso)
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # Fallback apenas para desenvolvimento; em produção deve vir do .env
    ENCRYPTION_KEY = Fernet.generate_key().decode()
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

###############################################################################
## REQUISITO 1.9 - SESSÕES COM TEMPO DE EXPIRAÇÃO (30 MINUTOS)
## REQUISITO 3.1 & 3.2 - COMUNICAÇÃO PROTEGIDA (COOKIES SEGUROS)
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

# BANCO DE DADOS
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=3306
    )

# FUNÇÕES DE APOIO À CRIPTOGRAFIA (REQUISITO 3.4 & 3.7)
def criptografar_dado(dado):
    return cipher_suite.encrypt(dado.encode()).decode()

def descriptografar_dado(dado_cripto):
    try:
        return cipher_suite.decrypt(dado_cripto.encode()).decode()
    except:
        return "{}" # Fallback para evitar quebra de sistema

# VALIDAÇÕES (CONFORMIDADE LGPD - REQUISITO 4.3 MINIMIZAÇÃO)
def validar_email(email):
    if not email: return None
    try:
        email_info = validate_email(email, check_deliverability=False)
        email = email_info.normalized
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email): return None
        return email
    except EmailNotValidError: return None

def validar_senha(senha):
    if not senha: return "Senha obrigatória"
    if len(senha) < 8: return "Senha deve ter no mínimo 8 caracteres"
    if not re.search(r"[A-Z]", senha): return "Senha precisa de letra maiúscula"
    if not re.search(r"\d", senha): return "Senha precisa de número"
    if not re.search(r"[!@#$%&*]", senha): return "Senha precisa de caractere especial"
    return None

###############################################################################
## REQUISITO 1 - LOGIN E AUTENTICAÇÃO PRIMÁRIA
###############################################################################
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        senha = request.form.get("senha") or ""

        if not email:
            return render_template("login.html", erro="Email inválido")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            conn.close()
            return render_template("login.html", erro="Usuário ou senha inválidos")

        ###############################################################################
        ## REQUISITO 1.11 - PROTEÇÃO CONTRA FORÇA BRUTA (BLOQUEIO POR 5 MINUTOS)
        ###############################################################################
        bloqueado_ate = usuario[3]
        if bloqueado_ate and bloqueado_ate > time.time():
            conn.close()
            return render_template("login.html", erro="Conta bloqueada temporariamente.")

        ###############################################################################
        ## REQUISITO 1.1 - HASH SEGURO (BCRYPT) / REQUISITO 1.3 - SALT ÚNICO
        ###############################################################################
        stored_hash = usuario[1].encode() if isinstance(usuario[1], str) else usuario[1]
        if not bcrypt.checkpw(senha.encode(), stored_hash):
            tentativas = (usuario[6] or 0) + 1
            if tentativas >= 5:
                bloqueio = time.time() + 300 
                cursor.execute("UPDATE usuarios SET bloqueado_ate = %s, tentativas = 0 WHERE email = %s", (bloqueio, email))
            else:
                cursor.execute("UPDATE usuarios SET tentativas = %s WHERE email = %s", (tentativas, email))
            
            conn.commit()
            conn.close()
            ###############################################################################
            ## REQUISITO 5.2 - LOGS DE FALHAS DE AUTENTICAÇÃO
            ###############################################################################
            print(f"[AUDITORIA] Falha de login: {email}")
            return render_template("login.html", erro="Usuário ou senha inválidos")

        # LIMPA BLOQUEIOS APÓS SUCESSO
        cursor.execute("UPDATE usuarios SET tentativas = 0, bloqueado_ate = 0 WHERE email = %s", (email,))
        conn.commit()
        conn.close()

        session["email_temp"] = email
        # REQUISITO 1.5 & 1.6 - REDIRECIONAMENTO PARA 2FA
        if usuario[5] == 0: return redirect("/qr")
        else: return redirect("/2fa")

    return render_template("login.html", sucesso=session.pop("sucesso", None))

###############################################################################
## REQUISITO 1.1, 1.3 & 3.4 - CADASTRO COM CRIPTOGRAFIA EM REPOUSO
###############################################################################
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        senha = request.form.get("senha")
        confirmar = request.form.get("confirmar")

        if not email: return render_template("cadastro.html", erro="Email inválido")
        
        erro_senha = validar_senha(senha)
        if erro_senha: return render_template("cadastro.html", erro=erro_senha)

        if senha != confirmar: return render_template("cadastro.html", erro="Senhas não conferem")

        # REQUISITO 1.1 - BCrypt Hash
        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
        chave_2fa = pyotp.random_base32()
        
        ###############################################################################
        ## REQUISITO 3.4 - DADOS SENSÍVEIS CRIPTOGRAFADOS EM REPOUSO (AES)
        ###############################################################################
        backup_codes = [secrets.token_hex(4) for _ in range(5)]
        # Salva os códigos de backup criptografados no banco
        backup_codes_cripto = criptografar_dado(json.dumps(backup_codes))

        conn = get_db(); cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO usuarios (email, senha_hash, chave_2fa, bloqueado_ate, backup_codes)
                VALUES (%s, %s, %s, %s, %s)
            """, (email, senha_hash, chave_2fa, 0, backup_codes_cripto))
            conn.commit()
            session["sucesso"] = "Cadastro realizado com sucesso!"
            return redirect("/")
        except:
            return render_template("cadastro.html", erro="E-mail já cadastrado.")
        finally:
            conn.close()

    return render_template("cadastro.html")

###############################################################################
## REQUISITO 1.5 - AUTENTICAÇÃO DE DOIS FATORES (2FA)
###############################################################################
@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    email = session.get("email_temp")
    if not email: return redirect("/")

    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT chave_2fa, backup_codes FROM usuarios WHERE email = %s", (email,))
    resultado = cursor.fetchone()
    conn.close()

    if not resultado: return redirect("/")

    chave_2fa = resultado[0]
    ###############################################################################
    ## REQUISITO 3.4 - DESCRIPTOGRAFIA DE DADOS EM REPOUSO PARA USO
    ###############################################################################
    backup_codes = json.loads(descriptografar_dado(resultado[1]))
    totp = pyotp.TOTP(chave_2fa)

    if request.method == "POST":
        codigo = request.form["codigo"]

        if codigo in backup_codes:
            backup_codes.remove(codigo)
            nova_lista_cripto = criptografar_dado(json.dumps(backup_codes))
            conn = get_db(); cursor = conn.cursor()
            cursor.execute("UPDATE usuarios SET backup_codes = %s WHERE email = %s", (nova_lista_cripto, email))
            conn.commit(); conn.close()
            session["user"] = email
            return redirect("/dashboard")

        if totp.verify(codigo):
            session["user"] = email
            ###############################################################################
            ## REQUISITO 5.1 - LOGS DE AUTENTICAÇÃO COM SUCESSO
            ###############################################################################
            print(f"[AUDITORIA] Login 2FA sucesso: {email}")
            return redirect("/dashboard")

        return render_template("2fa.html", erro="Código inválido")

    return render_template("2fa.html")

###############################################################################
## REQUISITO 2 - RECUPERAÇÃO DE SENHA (ENTREGA 3)
###############################################################################
@app.route("/recuperacao", methods=["GET", "POST"])
def recuperacao():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        if email:
            conn = get_db(); cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE email = %s", (email,))
            if cursor.fetchone():
                # REQUISITO 2.2 - TOKEN CRIPTOGRAFICAMENTE SEGURO
                token = secrets.token_urlsafe(32)
                # REQUISITO 2.3 - EXPIRAÇÃO EM 1 HORA
                expiracao = int(time.time()) + 3600 
                cursor.execute("UPDATE usuarios SET reset_token = %s, token_expiracao = %s WHERE email = %s", (token, expiracao, email))
                conn.commit()
                # REQUISITO 2.6 - LOG DE SOLICITAÇÃO
                print(f"[SEGURANÇA] Recuperação enviada para {email}: URL http://localhost:5000/resetar?token={token}&email={email}")
            conn.close()
        return render_template("recuperacao.html", sucesso="Instruções enviadas se o e-mail existir.")
    return render_template("recuperacao.html")

@app.route("/resetar", methods=["GET", "POST"])
def resetar():
    email = request.args.get("email") or request.form.get("email")
    token_url = request.args.get("token") or request.form.get("token")

    if request.method == "POST":
        nova_senha = request.form.get("senha")
        conn = get_db(); cursor = conn.cursor()
        cursor.execute("SELECT reset_token, token_expiracao FROM usuarios WHERE email = %s", (email,))
        dados = cursor.fetchone()

        # REQUISITO 2.5 - VALIDAÇÃO DE EXPIRAÇÃO
        if not dados or dados[0] != token_url or int(time.time()) > dados[1]:
            conn.close()
            return render_template("resetar.html", erro="Token inválido ou expirado.", email=email, token=token_url)

        erro_senha = validar_senha(nova_senha)
        if erro_senha:
            conn.close()
            return render_template("resetar.html", erro=erro_senha, email=email, token=token_url)

        # REQUISITO 2.4 - INVALIDAÇÃO DO TOKEN APÓS USO
        senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt())
        cursor.execute("UPDATE usuarios SET senha_hash = %s, reset_token = NULL, token_expiracao = 0 WHERE email = %s", (senha_hash, email))
        conn.commit(); conn.close()

        # REQUISITO 2.7 - REGISTRO DE SUCESSO
        print(f"[AUDITORIA] Senha redefinida para {email}")
        return render_template("login.html", sucesso="Senha redefinida com sucesso!")

    return render_template("resetar.html", email=email, token=token_url)

###############################################################################
## REQUISITO 1.10 - INVALIDAÇÃO DE SESSÃO NO LOGOUT
###############################################################################
@app.route("/logout")
def logout():
    session.clear()
    response = redirect("/")
    # REQUISITO 3.1 - Cabeçalhos para evitar cache
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# DASHBOARD (PÁGINA PROTEGIDA)
@app.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect("/")
    return render_template("dashboard.html", email=session["user"])

# QR CODE (REQUISITO 1.5)
@app.route("/qr")
def qr():
    if "email_temp" not in session: return redirect("/")
    email = session["email_temp"]
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT chave_2fa FROM usuarios WHERE email = %s", (email,))
    res = cursor.fetchone(); conn.close()
    
    totp = pyotp.TOTP(res[0])
    uri = totp.provisioning_uri(name=email, issuer_name="Sistema_Seguro")
    img = qrcode.make(uri)
    buf = io.BytesIO(); img.save(buf, format="PNG")
    return render_template("qr.html", qr_code=base64.b64encode(buf.getvalue()).decode())

@app.route("/qr-confirm", methods=["POST"])
def qr_confirm():
    email = session.get("email_temp")
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET twofa_ativo = TRUE WHERE email = %s", (email,))
    conn.commit(); conn.close()
    return redirect("/2fa")

if __name__ == "__main__":
    # REQUISITO 3.1 - Em produção usar HTTPS real, ssl_context='adhoc' gera um certificado temporário automaticamente
   app.run(debug=True, ssl_context='adhoc')

