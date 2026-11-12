# Lecciones aprendidas

Hallazgos técnicos y de criterio de análisis recogidos a lo largo de todo el proyecto. Volver al [README principal](../README.md).

## 📚 Lecciones aprendidas

- **El agente de Wazuh no lee Sysmon por defecto.** Hubo que agregar manualmente los canales al `ossec.conf` del agente.

- **Bug documentado y sin fix oficial del agente de Wazuh en Windows** (`EvtFormatMessage() ... 15029`). Reportado desde 2020, sin solución confirmada a fines de 2024. Reproducido dos veces, reaparece en ~20 minutos de sesión activa.

- **Las wildcard queries de OpenSearch sobre campos `keyword` son sensibles a mayúsculas/minúsculas.**

- **Windows Defender bloquea automáticamente firmas conocidas** (Mimikatz, Squiblydoo remoto, Mshta+VBScript+PowerShell, PsExec/Impacket) — pero **no todas las técnicas tienen firma**: WMI remoto pasó completamente desapercibido, dependiendo enteramente de detección por comportamiento.

- **Windows restringe por defecto el movimiento lateral con cuentas locales** vía `LocalAccountTokenFilterPolicy` — una protección real que detendría este ataque en un entorno corporativo bien configurado.

- **PsExec y WMI requieren grupos de firewall distintos**: "Compartir archivos e impresoras" (SMB) vs. "Instrumental de administración de Windows (WMI)" (DCOM/RPC).

- **El patrón de `wmiexec.py` es un IOC muy específico y detectable**: redirección de salida a `ADMIN$\__<timestamp epoch>`, visible en `ParentCommandLine` — una firma de comportamiento fiable aun sin firma de archivo.

- **No todo lo "sospechoso" es malicioso, incluso en reglas nativas del propio SIEM.** La regla `61640` de Wazuh genera falsos positivos con actividad DCOM completamente normal de Windows — un hallazgo que solo salió a la luz gracias al enriquecimiento automatizado con VirusTotal, mostrando el valor de la automatización para descubrir ruido que pasaría desapercibido revisando alertas una por una.

- **VirusTotal enriquece reputación de archivo; el SIEM detecta comportamiento.** `schtasks.exe` es y será siempre un binario limpio — la amenaza está en cómo se usa, no en el archivo en sí. Son capas complementarias, no sustitutas.

- **No todas las sub-técnicas de MITRE ATT&CK tienen atomics públicos.** T1574.002 no está disponible; se sustituyó documentando la ausencia.

- **Los NIDS sin inspección SSL no pueden ver dentro del tráfico HTTPS.**

- **Wazuh Manager en Docker no puede leer logs del host directamente sin bind-mount.** Se resolvió con un agente nativo de Wazuh en Ubuntu apuntando a `127.0.0.1`.

- **Un puerto que responde no significa el servicio correcto.** Un `404` (vs. timeout/connection refused) en la conexión al Indexer de Wazuh reveló que el puerto expuesto correspondía al Dashboard (5601→10443), no al Indexer real (9200) — ambos corriendo en contenedores Docker separados.

- **El "static data" de n8n solo persiste en ejecuciones de producción.** Las corridas manuales de prueba en el editor no graban los cambios al storage del workflow, aunque esté guardado — solo las ejecuciones disparadas por el propio trigger, con el workflow publicado y activo, persisten el estado entre corridas.

- **n8n restringe `require()` de módulos externos por seguridad, y no siempre se puede instalar en el lugar "obvio".** Instalar `sqlite3` directamente sobre el `package.json` interno de n8n falló por el protocolo de workspaces (`pnpm`) que usa internamente; hubo que instalarlo en una carpeta separada y exponerla vía `NODE_PATH` + `NODE_FUNCTION_ALLOW_EXTERNAL`.

- **Un cartel de error de UI no siempre significa un bug de lógica.** Una sesión de navegador con la conexión websocket trabada generó mensajes de "Node was not executed" que parecían un problema en el código del nodo — un simple refresh de página resolvió lo que en un primer momento parecía requerir depuración de la query SQL.

- **Un resultado "sospechoso" a veces es el correcto.** Que VirusTotal reporte 0 detecciones en herramientas usadas por Atomic Red Team no es un fallo del pipeline — es la confirmación esperada de que son binarios legítimos de Microsoft, y el motivo exacto por el que la detección de LOLBins necesita telemetría de comportamiento (Sysmon + Wazuh), no solo reputación de archivos.

- **Prevención y detección son capas distintas, y una no garantiza la otra.** Cuando el AV bloquea un ataque antes de que se cree el proceso, el SIEM se queda sin ningún evento que correlacionar — el ataque "no pasó", pero tampoco *se hubiera visto* si hubiera pasado. Documentar honestamente ese punto ciego (en vez de simplemente marcar la técnica como "detectada" porque el resultado final fue seguro) es más valioso que ocultarlo.

- **Al editar reglas custom en el contenedor de Wazuh Manager sin editores instalados** (imágenes mínimas sin `nano`/`vi`), la forma confiable es `docker cp` hacia/desde el host para editar ahí, y **siempre corregir permisos** después de copiar el archivo de vuelta (`chown wazuh:wazuh`, `chmod 660`) — de lo contrario el Manager falla en leerlo con un `Permission denied` silencioso, sin marcarlo como error de sintaxis, y sigue evaluando solo las reglas nativas sin avisar que la regla custom nunca se cargó.

