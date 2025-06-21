# 🔐 PassLocker

Um simples e seguro gerenciador de senhas em **Go** para armazenar e criptografar suas credenciais (`serviço`, `usuário` e `senha`) de maneira totalmente local e segura.

---

## ⚡️ Funcionalidades
- ✅ Adição de novas credenciais
- 👁️ Listagem e recuperação de credenciais
- 🔐 Criptografia AES‑GCM para garantir confidencialidade e integridade
- 🗝️ Derivação de chave com PBKDF2 + SHA‑256
- 📁 Os dados são armazenados no arquivo `vault.json`
- 🔥 Nenhuma informação sensível salva em texto claro
- 👤 Autenticação por senha mestra definida pelo usuário

---

## 🛠️ Requisitos
- **Go 1.22.4** ou superior
- Sistema Unix‑like (Parrot OS, Ubuntu, etc.)
- Git instalado para clonagem e controle de versão

---

## 🚀 Instalação e Configuração
```bash
# 1️⃣ Clone o repositório
git clone https://github.com/F3rnandesBy/passlocker.git
cd passlocker

# 2️⃣ Instale as dependências
go mod tidy

# 3️⃣ Compile ou rode direto
go run passlocker.go

