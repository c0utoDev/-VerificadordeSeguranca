# 🛡️ URL Security Scanner

Um aplicativo web full-stack simples e eficiente para análise de segurança de URLs. O sistema verifica a validade do certificado SSL/TLS de um domínio e consulta a API do **VirusTotal** para identificar possíveis ameaças (malware, phishing, etc.).

---

## 🚀 Funcionalidades

- **Validação de SSL/TLS:** Verifica se o site possui um certificado de segurança válido na porta 443.
- **Análise de Reputação (VirusTotal v3):** 
  - Consulta o banco de dados do VirusTotal codificando a URL em Base64URL.
  - Caso a URL seja inédita/desconhecida, o sistema a submete automaticamente para análise na plataforma.
- **Interface Web Limpa:** Uma página intuitiva com feedback em tempo real (loading e exibição detalhada de motores maliciosos/suspeitos).

---

## 🛠️ Tecnologias Utilizadas

- **Back-end:** Node.js, Express, Axios, Dotenv
- **Front-end:** HTML5, CSS3, JavaScript (Vanilla)
- **APIs & Protocolos:** VirusTotal API v3, HTTPS

---

## ⚙️ Pré-requisitos

Certifique-se de ter instalado em sua máquina:
- [Node.js](https://nodejs.org/) (versão 18 ou superior recomendada)
- Uma chave de API gratuita do [VirusTotal](https://www.virustotal.com/)

---

## 📥 Instalação e Configuração

1. **Clone o repositório ou acesse a pasta do projeto:**
   ```bash
   cd url-checker
