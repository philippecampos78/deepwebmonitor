# DeepWebMonitor

Ferramenta interna do SOC para monitorar a exposição dos clientes em fontes
públicas de inteligência de ameaças e gerar relatórios.

## Fontes (todas gratuitas)

| Fonte | O que encontra | Precisa de chave? |
|---|---|---|
| **Have I Been Pwned** | Se o próprio site do cliente já sofreu vazamento (catálogo público). Com a chave do plano já contratado: e-mails vazados de domínios verificados no painel e e-mails monitorados. | Não (opcional) |
| **ransomware.live** | Cliente listado em site de vazamento de grupo de ransomware. | Não |
| **Hudson Rock (OSINT)** | Funcionários/usuários com credenciais roubadas por malware infostealer. | Não |
| **dnstwist** | Domínios parecidos registrados (phishing / typosquatting). Roda localmente. | Não |

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

## Cuidados (LGPD e segurança)

- Tenha autorização em contrato de cada cliente para o monitoramento.
- Senhas devolvidas pelas fontes não são gravadas.
- Links `.onion` aparecem só como texto; não os acesse da rede corporativa.
- Os dados ficam em `data/deepwebmonitor.db`. Proteja esse arquivo (BitLocker).

## Testes

```powershell
.venv\Scripts\python.exe -m pytest
```
