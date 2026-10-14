@echo off
REM Inicia o DeepWebMonitor no Windows. Na primeira vez, prepara o ambiente.
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Criando ambiente Python...
    python -m venv .venv || goto :erro
)

echo [2/3] Instalando/atualizando dependencias...
".venv\Scripts\python.exe" -m pip install -q --upgrade pip
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt || goto :erro

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo.
    echo Arquivo .env criado. Edite-o ^(senha, nome da empresa^) e rode este script de novo.
    notepad .env
    goto :fim
)

echo [3/3] Site disponivel em http://127.0.0.1:8000  ^(Ctrl+C para parar^)
start "" http://127.0.0.1:8000
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
goto :fim

:erro
echo.
echo Ocorreu um erro. Verifique se o Python esta instalado: python --version
pause

:fim
