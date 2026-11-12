# Validación de reglas y hardening de Suricata

Metodología y hallazgos de la validación de las 12 reglas custom de Wazuh/Sysmon contra telemetría real, y la instalación/hardening de Suricata como NIDS, incluyendo su integración con Wazuh. Volver al [README principal](../README.md).

---

Todo lo de abajo se validó contra telemetría y tráfico de ataque **real** (no simulaciones sintéticas), siguiendo la filosofía de reducir ruido y falsos negativos antes de dar por buena una regla.

### 1. Validación de reglas custom de Wazuh/Sysmon

**Metodología:** en vez de probar las reglas con JSON sintético en `wazuh-logtest`, se generó telemetría real desde la VM Windows (PowerShell, tareas programadas, LOLBins, Impacket) y ataques reales desde Kali, confirmando cada regla contra el log de alertas real del manager.

> **Hallazgo clave:** `wazuh-logtest` decodifica el JSON crudo con el decoder genérico `json`, **no** con `windows_eventchannel`. Como las reglas de Sysmon dependen de la cadena de decoders nativa (`60000` → `60004` → `61613` → `92213`), un test sintético nunca activa esa cadena. Para estas reglas, la única validación confiable es telemetría real generada por Sysmon.

**12 reglas validadas**, incluyendo:
- Detección de PowerShell con comando en Base64, Rundll32 LOLBin, Regsvr32 (Squiblydoo), tareas programadas sospechosas, side-loading de GUP.exe, patrón de Impacket `wmiexec.py`, uso de BITSAdmin, volcado de LSASS vía `comsvcs.dll`, descarga de Mimikatz.
- 3 reglas de reducción de ruido (falsos positivos conocidos: archivos temporales de PowerShell, artefactos de compilación en memoria de `Add-Type`, lanzamiento legítimo de `explorer.exe` vía DCOM).

**Dos reglas rotas encontradas y corregidas** (100030 – Rundll32, 100090 – BITSAdmin): nunca disparaban porque su `if_group`/`if_sid` apuntaba a un grupo o regla nativa que no aplicaba a ese tráfico (`sysmon_eid1_detections` es solo una etiqueta compartida por reglas no relacionadas; `92005` exige específicamente `cmd.exe /c` + intérprete, lo cual no cubre `bitsadmin.exe`). Se corrigieron apuntando al grupo base universal `sysmon_event1`, que cubre cualquier evento Sysmon ID 1.

> **Hallazgo de correlación de Wazuh:** dos reglas hijas del mismo `if_sid`/`if_group` que matchean sobre el **mismo nombre de campo** (ej. ambas sobre `win.eventdata.targetFilename`) no coexisten de forma confiable — solo una de las dos "gana" el ciclo de evaluación, independientemente de si sus condiciones son distintas. Reglas que usan **campos distintos** (ej. `targetFilename` vs `image`) sí coexisten sin problema. Esto se descubrió empíricamente aislando variables una por una (regex, backreferences, reglas de debug triviales) y obligó a fusionar dos reglas de excepción en una sola, usando el campo `image`.

> **Hallazgo de telemetría:** `Add-Type` (compilación en memoria de C# vía PowerShell) genera **dos eventos FileCreate (Sysmon EID 11) distintos** para el mismo artefacto `.dll`/`.cmdline`: uno con `image=csc.exe` (el compilador real) y un duplicado con `image=powershell.exe` (el proceso host .NET). Cualquier regla de supresión para este patrón debe contemplar ambos procesos.

### 2. Instalación y hardening de Suricata (NIDS)

**Decisión:** Suricata como NIDS único del lab, por ventajas de multi-threading y por integración nativa de su salida EVE JSON con el decoder/ruleset propio de Wazuh.

**Instalación y configuración** (`/etc/suricata/suricata.yaml`):
- `HOME_NET` ajustado a la red del lab (`192.168.64.0/24`)
- Interfaz de captura (`af-packet`) configurada sobre la interfaz real de la VM
- `threads: 1` (lab de 2 cores)
- Reglas custom copiadas a `/var/lib/suricata/rules/local.rules` y referenciadas en `rule-files`

> **Bug encontrado:** la lista `rule-files` incluía por defecto una entrada (`suricata.rules`) apuntando a un archivo que no existe hasta correr `suricata-update`. Esto hacía que Suricata **no cargara ninguna regla en absoluto** (ni siquiera las propias, presentes y bien formadas), reportando silenciosamente `"1 rule files specified, but no rules were loaded!"` sin señalar cuál entrada era la culpable. Se diagnosticó aislando la carga con el flag `-S <archivo>` (que bypassea `rule-files` y carga un único archivo directo), confirmando que el archivo propio cargaba perfecto en soledad. La solución fue eliminar la entrada inexistente de la lista.

**5 reglas de red validadas con tráfico real** generado entre las VMs del lab (no solo con `-T`/test mode, sino con Suricata corriendo en captura real sobre la interfaz):
- Descarga vía PowerShell (User-Agent `WindowsPowerShell` hacia red externa)
- Solicitud HTTP de archivo `.sct` (patrón Squiblydoo)
- Descarga de ejecutable `.exe` en texto plano
- Descarga desde `raw.githubusercontent.com` (simulada vía header `Host` manual, dado que GitHub sirve ese contenido por HTTPS en la práctica)
- Payload ICMP inusualmente grande (posible canal encubierto)

**Reducción de ruido:** la regla de descarga de `.exe` generaba falsos positivos constantes contra el tráfico legítimo de Windows Update (Delivery Optimization). Se agregó una condición negativa sobre el header HTTP (`content:!"windowsupdate.com"; http_header;`) que suprime esos falsos positivos sin afectar la detección de descargas reales de ejecutables desde otros orígenes. Validado en ambos sentidos: el falso positivo deja de generar alerta, y una descarga real sigue disparando normalmente.

**Persistencia:** Suricata corre como servicio `systemd` (`suricata.service`), habilitado para arrancar en el boot y con reinicio automático ante fallos — no se opera más con el comando manual `suricata -D`.

### 3. Integración Suricata + Wazuh

Se instaló un **agente de Wazuh** en la misma VM donde corre Suricata (separado del contenedor del manager), registrado contra el manager en `127.0.0.1` (mismo host), con un bloque `<localfile>` apuntando a `/var/log/suricata/eve.json` con `log_format: json`.

Confirmado end-to-end: las alertas de Suricata llegan al manager, son procesadas por el **decoder y ruleset nativo de Suricata de Wazuh** (sin necesidad de reglas custom adicionales), y aparecen como alertas con `rule.id: 86601` y grupo `suricata`, preservando el `signature_id` y la descripción original de la regla de red. Las alertas de red ahora son visibles en el mismo dashboard que las de Sysmon/endpoint.

