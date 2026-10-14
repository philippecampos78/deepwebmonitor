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
| **VirusTotal** | Domínio marcado como malicioso por antivírus e listas de bloqueio. | Chave gratuita |
| **Shodan InternetDB + CISA KEV** | Portas sensíveis abertas (RDP, bancos de dados...) e CVEs nos servidores do cliente; as exploradas ativamente viram críticas. | Não |
| **SPF / DKIM / DMARC** | Se o domínio pode ser falsificado em e-mails de phishing. | Não |
| **urlscan.io** | Páginas falsas com a marca do cliente ou copiando o visual do site. | Não (opcional) |
| **crt.sh** | Certificados recém-emitidos para domínios com o nome do cliente (sites falsos). | Não |
| **dnstwist** | Domínios parecidos registrados (phishing / typosquatting). Roda localmente. | Não |

### Chaves gratuitas (opcionais)

Coloque no `.env`. Fontes sem chave aparecem desativadas no painel.

- **GITHUB_TOKEN**: em https://github.com/settings/personal-access-tokens crie um
  token *fine-grained* com acesso "Public repositories (read-only)" e nenhuma permissão extra.
- **ABUSECH_AUTH_KEY**: em https://auth.abuse.ch/ (login com GitHub, Google ou LinkedIn).
- **OTX_API_KEY**: em https://otx.alienvault.com, menu *Settings* > *API Key*.
- **VIRUSTOTAL_API_KEY**: crie a conta em https://www.virustotal.com e copie a chave em
  *menu do perfil* > *API key* (plano gratuito: 4 consultas/minuto, 500/dia).
- **URLSCAN_API_KEY**: crie a conta em https://urlscan.io/user/signup e gere a chave em
  *Settings & API*. Sem ela, a busca pela marca só encontra domínios que começam com o nome.

As consultas DNS (SPF/DKIM/DMARC e IPs) usam DNS via HTTPS da Cloudflare por padrão
(`DNS_MODE=doh`), o que funciona atrás de proxy corporativo. Use `DNS_MODE=local`
para usar o DNS do computador.

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

## Atualizar para uma versão nova

Na pasta do projeto, rode:

```powershell
.\atualizar.bat
```

Ele baixa a versão nova, mostra qual versão ficou instalada e inicia o site. O seu
`.env` e os dados (`data/`) não são alterados. Toda vez que o site inicia, as
configurações novas do `.env.example` que faltarem no seu `.env` são acrescentadas
no final dele (vazias ou com o valor padrão); os valores que você já preencheu não mudam.

## Uso

1. Cadastre o cliente, os domínios e (opcional) e-mails importantes.
2. Em **Fontes da varredura**, marque as fontes que quer usar (ou use os atalhos
   *Todas*, *Só as rápidas* e *Nenhuma*) e clique em **Executar varredura**. A escolha
   fica salva para o cliente. As fontes marcadas como **lenta** (dnstwist, crt.sh e
   VirusTotal) podem levar alguns minutos. A página se atualiza sozinha até terminar.
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
