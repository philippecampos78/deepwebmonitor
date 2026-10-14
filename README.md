# DeepWebMonitor

Ferramenta interna do SOC para monitorar a exposição dos clientes em fontes
públicas de inteligência de ameaças e gerar relatórios.

## Fontes (todas gratuitas)

| Fonte | O que encontra | Precisa de chave? |
|---|---|---|
| **Have I Been Pwned** | Se o próprio site do cliente já sofreu vazamento (catálogo público). Com a chave do plano já contratado: e-mails vazados de domínios verificados no painel e e-mails monitorados. | Não (opcional) |
| **ransomware.live** | Cliente listado em site de vazamento de grupo de ransomware. | Não |
| **RansomLook** | Idem, segunda base (outros grupos). Lê os últimos `RANSOMLOOK_DAYS` dias. | Não |
| **Hudson Rock (OSINT)** | Funcionários/usuários com credenciais roubadas por malware infostealer. | Não |
| **Ahmia** | Menções ao domínio em sites .onion indexados (sem acessar a rede Tor). | Não |
| **GitHub + gitleaks** | Senhas, tokens e chaves expostos em repositórios públicos que citam o domínio. | Token gratuito do GitHub |
| **abuse.ch (URLhaus e ThreatFox)** | Site do cliente distribuindo malware ou usado como infraestrutura de ataque. | Chave gratuita |
| **AlienVault OTX** | Domínio citado em relatórios de ameaças da comunidade. | Não (opcional) |
| **crt.sh** | Certificados recém-emitidos para domínios com o nome do cliente (sites falsos). | Não |
| **dnstwist** | Domínios parecidos registrados (phishing / typosquatting). Roda localmente. | Não |

### Chaves gratuitas (opcionais)

Coloque no `.env`. Fontes sem chave aparecem desativadas no painel.

- **GITHUB_TOKEN**: em https://github.com/settings/personal-access-tokens crie um
  token *fine-grained* com acesso "Public repositories (read-only)" e nenhuma permissão extra.
- **ABUSECH_AUTH_KEY**: em https://auth.abuse.ch/ (login com GitHub, Google ou LinkedIn).
- **OTX_API_KEY**: em https://otx.alienvault.com, menu *Settings* > *API Key*.

### gitleaks (opcional, recomendado)

Sem o gitleaks, o GitHub usa regras internas mais simples. Para instalar no Windows:
baixe o arquivo `gitleaks_..._windows_x64.zip` em
https://github.com/gitleaks/gitleaks/releases, extraia o `gitleaks.exe` (por exemplo
em `C:\Ferramentas\`) e informe o caminho em `GITLEAKS_PATH` no `.env`. O painel
mostra se ele foi encontrado.

Cada fonte é um "coletor" em `app/collectors/`. Para adicionar uma fonte nova,
crie uma classe que herda de `Collector` e inclua em `app/collectors/__init__.py`.

## Como rodar no Windows 11

Pré-requisitos (uma vez só, no PowerShell):

```powershell
winget install Python.Python.3.12
winget install Git.Git
```

Baixar o projeto e iniciar:

```powershell
cd $HOME\Documents
git clone https://github.com/philippecampos78/deepwebmonitor.git
cd deepwebmonitor
git checkout claude/hibp-breach-report-site-hu86y4
.\iniciar.bat
```

Na primeira execução o script cria o arquivo `.env` e abre o Bloco de Notas:
defina `APP_PASSWORD`, `COMPANY_NAME` e, se quiser, `HIBP_API_KEY`. Salve, feche
e rode `.\iniciar.bat` de novo. O navegador abre em http://127.0.0.1:8000 e
pede o usuário/senha definidos no `.env`.

O site escuta somente em `127.0.0.1` (não fica acessível para outros
computadores da rede).

## Uso

1. Cadastre o cliente, os domínios e (opcional) e-mails importantes.
2. Clique em **Executar varredura**. A página se atualiza sozinha até terminar
   (o dnstwist pode levar alguns minutos por domínio).
3. Clique em **Gerar relatório** e use **Imprimir / Salvar em PDF**.

Achados já conhecidos não são duplicados; o relatório destaca como "Novo" o que
apareceu no período escolhido.

## Verificar senha

O menu **Verificar senha** confere se uma senha aparece em vazamentos públicos
(Pwned Passwords, do HIBP, gratuito). Só os 5 primeiros caracteres do hash SHA-1
saem do servidor (k-anonimato); a senha não é gravada nem registrada. Use com o
cliente para confirmar se a senha de uma conta exposta é a atual.

Nos relatórios, as senhas encontradas pelas fontes (ex.: Hudson Rock) aparecem
apenas **mascaradas** (ex.: `ab*******`), do jeito que a fonte entrega. Se algum
valor vier sem máscara, o site mascara antes de gravar.

## Identidade visual

Cores, fonte (Poppins, incluída em `app/static/fonts`, licença OFL) e logo seguem a
proposta comercial da UXGUARD. Nome, logo e rodapé dos relatórios são configuráveis
no `.env` (`COMPANY_NAME`, `COMPANY_LOGO`, `COMPANY_FOOTER`, `COMPANY_ADDRESS`).
O relatório tem versão escura (padrão) e clara, para impressão em papel.

## Cuidados (LGPD e segurança)

- Tenha autorização em contrato de cada cliente para o monitoramento.
- Senhas devolvidas pelas fontes não são gravadas.
- Links `.onion` aparecem só como texto; não os acesse da rede corporativa.
- Os dados ficam em `data/deepwebmonitor.db`. Proteja esse arquivo (BitLocker).

## Testes

```powershell
.venv\Scripts\python.exe -m pytest
```
