# Projeto Integrador – Políticas de Segurança da Informação
 
## Sobre o Projeto
 
Este projeto foi desenvolvido como parte da atividade da disciplina Políticas de Segurança da Informação, com o objetivo de aplicar na prática os conhecimentos estudados ao longo do curso. A proposta consistiu na criação de um sistema seguro de autenticação e gerenciamento de credenciais, utilizando tecnologias atuais e seguindo princípios da LGPD (Lei Geral de Proteção de Dados).
 
O sistema foi projetado para oferecer mais segurança no acesso dos usuários, protegendo informações sensíveis e reduzindo riscos comuns como vazamento de senhas, acessos indevidos e tentativas de invasão.
 
## Objetivo do Sistema
 
Desenvolver, implementar, documentar e comunicar cientificamente um sistema seguro de autenticação e gestão de credenciais, incorporando autenticação multifator, criptografia, recuperação segura de senhas, auditoria e conformidade com a LGPD, com fundamentação em normas técnicas e literatura científica revisada por pares. 
 
## Tecnologias Utilizadas
 
- **Python** – linguagem principal  
- **Flask** – framework web  
- **MySQL** – banco de dados relacional  
- **bcrypt** – hash seguro de senhas  
- **PyOTP** – autenticação em dois fatores (2FA)  
- **qrcode** – geração de QR Code para autenticação  
- **cryptography (Fernet)** – criptografia de dados sensíveis em repouso  
- **python-dotenv** – gerenciamento de variáveis de ambiente  
- **email-validator** – validação de e-mails  
 
## Estrutura do Projeto (MVC)

O projeto segue o padrão arquitetural **MVC (Model–View–Controller)** para melhor organização, separação de responsabilidades e escalabilidade.
```
│── app.py             # Arquivo principal da aplicação, responsável por iniciar o servidor Flask, configurar sessões, segurança e registrar os controllers.
│── requirements.txt   # Define as bibliotecas necessárias para rodar o projeto.
│── .env               # Arquivo de variáveis de ambiente utilizado para armazenar dados sensíveis.
│
├── controllers/       # Gerencia o fluxo da aplicação: recebe requisições, aciona a lógica de negócio e retorna a resposta ao usuário.
│   └── auth_controller.py
│
├── models/            # Responsável pela comunicação com o banco de dados.
│   └── user_model.py
│
├── services/          # Responsável por funções auxiliares como validação de dados e criptografia.
│   ├── crypto_service.py    # Realiza criptografia e descriptografia de dados sensíveis, como códigos de backup.
│   └── validation_service.py # Valida dados de entrada, assegurando conformidade com regras de segurança.
│
├── database/          # Responsável pela configuração e gerenciamento da conexão com o banco de dados.
│   └── connection.py  # Centraliza a conexão com o banco (MySQL), utilizando variáveis de ambiente para maior segurança.
│
├── templates/         # Contém as páginas HTML da aplicação (interface do usuário)
│   ├── login.html
│   ├── cadastro.html
│   ├── 2fa.html
│   ├── qr.html
│   ├── dashboard.html
│   ├── recuperacao.html
│   └── resetar.html
│
└── static/            # Armazena arquivos estáticos da aplicação
```
### Organização:
- **Model** → acesso ao banco de dados  
- **View** → interface (HTML)  
- **Controller** → regras de negócio e rotas  
- **Services** → validações e criptografia   
 
## Funcionalidades Implementadas
 
O sistema permite o cadastro de usuários com validação de e-mail e definição de senha forte, exigindo critérios mínimos de segurança. As senhas são armazenadas de forma protegida utilizando hash com bcrypt e salt. Durante o login, há verificação das credenciais e proteção contra ataques de força bruta, com bloqueio temporário após múltiplas tentativas inválidas. Após a autenticação inicial, é exigido um segundo fator (2FA), integrado ao Google Authenticator por meio de QR Code, além da disponibilização de códigos de backup armazenados de forma criptografada.

O sistema também implementa criptografia de dados sensíveis, gerenciamento seguro de sessões com tempo de expiração e cookies protegidos, além de redirecionamento para HTTPS. Adicionalmente, são registrados logs de eventos relevantes, como tentativas de login e redefinições de senha, contribuindo para auditoria e monitoramento de segurança.
 
## Aplicação da LGPD
 
O projeto foi desenvolvido considerando princípios importantes da LGPD, especialmente no tratamento seguro de dados pessoais. O sistema coleta apenas informações necessárias para funcionamento, como e-mail e senha criptografada, evitando excesso de dados armazenados.
 
Também foram adotadas medidas técnicas de proteção, como criptografia, autenticação reforçada e controle de acesso, contribuindo para a privacidade e segurança das informações dos usuários.

## Segurança Implementada
 
O sistema incorpora diversas camadas de segurança:
 
- Hash de senhas com bcrypt  
- Criptografia de dados sensíveis  
- Autenticação multifator (2FA)  
- Tokens seguros para recuperação de senha  
- Proteção contra ataques de força bruta  
- Proteção contra enumeração de usuários  
- Sessões seguras e controle de acesso  
 
## Conclusão
 
O desenvolvimento deste projeto permitiu aplicar conceitos essenciais de segurança da informação em uma solução prática e funcional. A aplicação demonstra como mecanismos como criptografia, autenticação em dois fatores, controle de sessões e proteção contra ataques podem tornar sistemas mais seguros.
 
Dessa forma, o trabalho atende ao objetivo proposto pela disciplina e reforça a importância da implementação de boas práticas de segurança e conformidade com a LGPD em sistemas modernos.

Para melhor visualização, apresentamos abaixo os testes realizados nas interfaces de cadastro, login e configuração de autenticação de dois fatores (2FA), e a tela de boas-vindas pós-autenticação do usuário.

<img width="1764" height="1022" alt="image" src="https://github.com/user-attachments/assets/28c7b088-cf9e-481e-add6-a4e35136a519" />


#### Integrantes: Ágatha Mami Takaki Ayama | Alana Vagnini Barbosa | Ana Carolina da Silva
