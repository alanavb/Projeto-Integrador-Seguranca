CREATE DATABASE db_auth;

USE db_auth;

CREATE TABLE usuarios (
    email VARCHAR(255) PRIMARY KEY,
    senha_hash BLOB,
    chave_2fa VARCHAR(255),
    bloqueado_ate DOUBLE,
    backup_codes TEXT
);

ALTER TABLE usuarios ADD COLUMN twofa_ativo BOOLEAN DEFAULT FALSE;
ALTER TABLE usuarios MODIFY bloqueado_ate BIGINT;
ALTER TABLE usuarios ADD tentativas INT DEFAULT 0;

ALTER TABLE usuarios 
ADD COLUMN reset_token VARCHAR(255) DEFAULT NULL,
ADD COLUMN token_expiracao BIGINT DEFAULT 0;

ALTER TABLE usuarios 
ADD COLUMN reset_token VARCHAR(255),
ADD COLUMN token_expiracao BIGINT;

ALTER TABLE usuarios DROP PRIMARY KEY;
ALTER TABLE usuarios ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY;
ALTER TABLE usuarios ADD UNIQUE (email);

SELECT * FROM usuarios;
SELECT email, reset_token, token_expiracao FROM usuarios;
