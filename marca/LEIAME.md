# Arquivos da marca UXGUARD

| Arquivo | Uso |
|---|---|
| `logo_uxguard_preto.svg` | Logo original (vetorial, preta), como recebida. Guarde esta versão: é a fonte das demais. |
| `../app/static/img/logo-uxguard-preto.png` | Versão preta usada pelo site em fundo claro (relatório para impressão). |
| `../app/static/img/logo-uxguard-branco.png` | Versão branca usada pelo site em fundo escuro (topo do site e relatório escuro). |

As versões PNG foram geradas a partir do SVG em 2362 × 860 px, com fundo transparente;
a branca é a preta com as cores invertidas (o degradê do escudo vira cinza claro).

Para trocar a logo do site, aponte `COMPANY_LOGO` (preta) e `COMPANY_LOGO_BRANCA`
(branca) no `.env` para os novos arquivos: caminho dentro de `app/static` ou caminho
completo (ex.: `C:\Imagens\logo.png`).
