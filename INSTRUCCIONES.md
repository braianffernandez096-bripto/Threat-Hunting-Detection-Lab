# Actualización del repositorio — Noviembre 2026

Este paquete trae la versión actualizada de la implementación: NIDS migrado a Suricata, pipeline de n8n con notificación por Telegram, el set completo de reglas de Wazuh/Sysmon sincronizado, y una guía de instalación paso a paso.

## Archivos a subir (pisan o completan los existentes)

- `README.md`
- `docs/INSTALACION.md` (nuevo — guía de instalación paso a paso de todo el lab)
- `detections/T1218.011-rundll32/rule.xml`
- `detections/T1197-bitsadmin/rule.xml`
- `detections/T1059.001-powershell-encoded/local_rules_custom.xml`
- `detections/T1218.010-regsvr32-squiblydoo/rule.xml`
- `detections/T1053.005-scheduled-tasks/rule.xml`
- `detections/T1574.001-dll-sideloading/rule.xml`
- `detections/T1047-wmi-lateral-movement/rule.xml`
- `detections/T1003.001-lsass-access/rule.xml`
- `detections/T1003-mimikatz/rule.xml`

## Carpetas/archivos que ya no corresponden a esta versión

- `detections/snort-nids/` → el NIDS ahora es Suricata (`detections/suricata-nids/`)
- `detections/local_rules_custom.xml` (el archivo suelto en la raíz de `detections/`) → consolidado en `detections/sysmon-rules/local_rules.xml`
- `docs/README-update-nov2026.md` → ya integrado en el `README.md` principal

## Imágenes a sacar de `docs/screenshots/`

Revisé las 19 capturas del repo contra lo documentado. 17 coinciden perfecto con su descripción. Dos quedaron desactualizadas porque muestran el canal de notificación anterior (Slack), que ya no se usa:

- `docs/screenshots/11-n8n-workflow-canvas-complete.png` → el nodo final muestra un webhook de Slack
- `docs/screenshots/19-live-demo-slack-notification.png` → captura de la notificación en Slack

Ya saqué las referencias a estas dos del `README.md`. Podés borrar los archivos del repo (no se usan en ningún lado más). Si en algún momento querés documentar visualmente el pipeline actual, se podrían reemplazar por capturas equivalentes del workflow en n8n y de una alerta llegando a Telegram.
