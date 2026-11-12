# Reorganización del repositorio — reducir el README y agregar guía de uso

## 1. Subir `README.md`
Pisa el actual. Pasó de 594 a ~210 líneas: se mantiene todo lo esencial (badges, resumen, arquitectura, stack, cobertura MITRE, estructura) y el contenido extenso se movió a documentos separados, enlazados desde una nueva sección "📂 Documentación detallada".

También se agregó una sección nueva, "🧪 Cómo usar este lab", con el comando de `git clone` y una guía rápida de qué seguir según lo que alguien quiera reproducir (el lab completo, solo las reglas, o solo el pipeline de Telegram).

## 2. Subir estos 4 archivos nuevos a `docs/`

- `docs/CASOS-DE-DETECCION.md` — todo el detalle técnico de cada técnica MITRE ATT&CK (antes eran 3 secciones largas del README)
- `docs/VALIDACION-REGLAS-SURICATA.md` — metodología de validación de las 12 reglas de Wazuh + hardening de Suricata
- `docs/PIPELINE-AUTOMATIZACION.md` — VirusTotal, n8n, SQLite y Telegram, de punta a punta
- `docs/LECCIONES-APRENDIDAS.md` — la lista completa de hallazgos técnicos

No se perdió ningún contenido: es el mismo texto, reglas y capturas de siempre, solo reorganizado en archivos más chicos y enlazados entre sí (cada uno tiene un link de vuelta al README).

## Nada más para borrar

Todas las imágenes, reglas y el workflow de n8n quedan exactamente donde estaban — esta ronda solo tocó `README.md` y agregó los 4 archivos de `docs/` de arriba.
