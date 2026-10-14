@echo off
REM Baixa a versao mais nova do DeepWebMonitor e inicia o site.
REM Seu .env e seu banco de dados (pasta data) nao sao alterados.
cd /d "%~dp0"

echo Baixando atualizacoes...
git pull --ff-only origin claude/hibp-breach-report-site-hu86y4
if errorlevel 1 (
    echo.
    echo Nao foi possivel atualizar. Envie a mensagem acima para o suporte.
    echo Dica: rode "git status" para ver arquivos alterados nesta pasta.
    pause
    goto :eof
)

echo.
git log -1 --format="Versao instalada: %%h - %%s (%%cd)" --date=format:%%d/%%m/%%Y
echo.
call iniciar.bat
