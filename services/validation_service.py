import re
from email_validator import validate_email, EmailNotValidError

###############################################################################
## REQUISITO 4.3 - MINIMIZAÇÃO DE DADOS (VALIDAÇÕES)
###############################################################################
def validar_email(email):
    if not email: return None
    try:
        email_info = validate_email(email, check_deliverability=False)
        email = email_info.normalized.lower ()
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
