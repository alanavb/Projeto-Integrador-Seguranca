from database.connection import get_db

###############################################################################
## LOGIN
###############################################################################
def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


###############################################################################
## CADASTRO
###############################################################################
def create_user(email, senha_hash, chave_2fa, backup_codes_cripto):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO usuarios (email, senha_hash, chave_2fa, bloqueado_ate, backup_codes)
        VALUES (%s, %s, %s, %s, %s)
    """, (email, senha_hash, chave_2fa, 0, backup_codes_cripto))
    conn.commit()
    conn.close()


###############################################################################
## FORÇA BRUTA / BLOQUEIO
###############################################################################
def update_tentativas(email, tentativas):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET tentativas = %s WHERE email = %s", (tentativas, email))
    conn.commit()
    conn.close()

def bloquear_usuario(email, bloqueio):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET bloqueado_ate = %s, tentativas = 0 WHERE email = %s", (bloqueio, email))
    conn.commit()
    conn.close()

def limpar_bloqueio(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET tentativas = 0, bloqueado_ate = 0 WHERE email = %s", (email,))
    conn.commit()
    conn.close()


###############################################################################
## 2FA
###############################################################################
def get_2fa_data(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT chave_2fa, backup_codes FROM usuarios WHERE email = %s", (email,))
    data = cursor.fetchone()
    conn.close()
    return data

def update_backup_codes(email, backup_codes_cripto):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET backup_codes = %s WHERE email = %s", (backup_codes_cripto, email))
    conn.commit()
    conn.close()

def get_chave_2fa(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT chave_2fa FROM usuarios WHERE email = %s", (email,))
    res = cursor.fetchone()
    conn.close()
    return res

def ativar_2fa(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET twofa_ativo = TRUE WHERE email = %s", (email,))
    conn.commit()
    conn.close()


###############################################################################
## RECUPERAÇÃO DE SENHA
###############################################################################
def update_reset_token(email, token, expiracao):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET reset_token = %s, token_expiracao = %s WHERE email = %s",
        (token, expiracao, email)
    )
    conn.commit()
    conn.close()

def get_reset_data(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT reset_token, token_expiracao FROM usuarios WHERE email = %s", (email,))
    data = cursor.fetchone()
    conn.close()
    return data

def update_password(email, senha_hash):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET senha_hash = %s, reset_token = NULL, token_expiracao = 0 WHERE email = %s",
        (senha_hash, email)
    )
    conn.commit()
    conn.close()