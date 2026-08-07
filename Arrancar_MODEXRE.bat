@echo off
title MODEXRE
REM %~dp0 = carpeta donde está este propio .bat (con la barra final
REM incluida). Antes la ruta estaba fija a C:\Proyectos\MODEXRE, así
REM que solo funcionaba si el repositorio se clonaba exactamente ahí
REM -- con %~dp0 funciona sin importar en qué carpeta se haya clonado.
cd /d %~dp0
streamlit run frontend\app.py
