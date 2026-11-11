# Instrucciones de limpieza — Noviembre 2026

## 1. Borrar del repo (ya no corresponden)

- `detections/snort-nids/` (carpeta completa) → reemplazada por `detections/suricata-nids/`
- `detections/local_rules_custom.xml` (el archivo suelto en la raíz de `detections/`, NO la carpeta `sysmon-rules/`) → reemplazado por `detections/sysmon-rules/local_rules.xml`, que ya subiste antes
- `docs/README-update-nov2026.md` → su contenido ya está fusionado dentro del `README.md` principal, queda duplicado

## 2. Reemplazar con los archivos de este paquete

- `README.md` → pisa el de la raíz (corrige la estructura del repo en el árbol de carpetas: ya no menciona `local_rules_custom.xml` suelto ni el `db/` como carpeta top-level)
- `detections/T1218.011-rundll32/rule.xml` → **corrige la regla 100030**, que tenía la referencia rota (`if_group: sysmon_eid1_detections`, nunca disparaba)
- `detections/T1197-bitsadmin/rule.xml` → **corrige la regla 100090**, que tenía la referencia rota (`if_sid: 92005`, nunca disparaba)
- `detections/T1059.001-powershell-encoded/local_rules_custom.xml` → actualiza la regla 100011 (ahora cubre `csc.exe` Y `powershell.exe`) y el `if_group` de la 100020
- `detections/T1218.010-regsvr32-squiblydoo/rule.xml`
- `detections/T1053.005-scheduled-tasks/rule.xml`
- `detections/T1574.001-dll-sideloading/rule.xml`
- `detections/T1047-wmi-lateral-movement/rule.xml`
- `detections/T1003.001-lsass-access/rule.xml`
- `detections/T1003-mimikatz/rule.xml`

Estos últimos 6 solo tenían un cambio cosmético/de consistencia: `if_group` actualizado de `sysmon_eid1_detections` a `sysmon_event1` para que coincidan exactamente con el archivo consolidado y validado (`detections/sysmon-rules/local_rules.xml`), que es la fuente de verdad real del lab.

## No se tocan (están bien así)

- `detections/T1140-certutil-masquerade/rule.xml` (placeholder, cubierto por reglas nativas)
- `detections/T1569.002-psexec/rule.xml` (placeholder, cubierto por regla nativa)
- `detections/T1218.005-mshta-partial/rule.xml` (placeholder, sin regla custom por diseño — telemetría nunca llegó)
- `detections/virustotal-enrichment/`, `docs/screenshots/`, `n8n-workflows/db/` — sin cambios
