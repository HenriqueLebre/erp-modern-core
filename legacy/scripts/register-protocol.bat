@echo off
REM ============================================
REM Register sysfood:// Protocol Handler
REM ============================================

echo Registrando protocol handler sysfood://...

REM Criar chave do protocolo
reg add "HKEY_CURRENT_USER\Software\Classes\sysfood" /ve /d "URL:SysFood Protocol" /f
reg add "HKEY_CURRENT_USER\Software\Classes\sysfood" /v "URL Protocol" /t REG_SZ /d "" /f

REM Definir ?cone (opcional)
reg add "HKEY_CURRENT_USER\Software\Classes\sysfood\DefaultIcon" /ve /d "C:\ERP\sysfood.exe,1" /f

REM Definir comando de execu??o
REM AJUSTE O CAMINHO PARA O SEU EXE!
reg add "HKEY_CURRENT_USER\Software\Classes\sysfood\shell\open\command" /ve /d "\"C:\ERP\sysfood.exe\" \"%%1\"" /f

echo.
echo  Protocol handler registrado com sucesso!
echo.
echo Para testar, abra no navegador:
echo sysfood://test?token=123456
echo.
pause
