###############################################################################
## REQUISITO 3.5 - USO DE ALGORITMO CRIPTOGRÁFICO 
###############################################################################
from cryptography.fernet import Fernet
import os

###############################################################################
## REQUISITO 3.6 - CHAVES CRIPTOGRÁFICAS PROTEGIDAS (ENCRYPTION_KEY)
###############################################################################
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    # Fallback apenas para desenvolvimento; em produção deve vir do .env
    ENCRYPTION_KEY = Fernet.generate_key().decode()

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

###############################################################################
## REQUISITO 3.4 & 3.7 - FUNÇÕES DE CRIPTOGRAFIA
###############################################################################
def criptografar_dado(dado):
    return cipher_suite.encrypt(dado.encode()).decode()

def descriptografar_dado(dado_cripto):
    try:
        return cipher_suite.decrypt(dado_cripto.encode()).decode()
    except:
        return "{}"  # Fallback para evitar quebra de sistema