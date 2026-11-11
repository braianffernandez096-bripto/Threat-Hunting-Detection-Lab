# Guía de instalación — Threat Hunting & Detection Lab

Paso a paso para levantar el lab completo desde cero: 3 VMs en red aislada, Wazuh como SIEM, Sysmon como fuente de telemetría del endpoint, Suricata como NIDS, y el pipeline de n8n con notificación por Telegram.

## 1. Topología de red

3 VMs en la misma red privada/aislada (`192.168.64.0/24` en este lab, ajustable):

| VM | Rol | IP (ejemplo) |
|---|---|---|
| Ubuntu Server | Wazuh Manager + Indexer + Dashboard (Docker) + Suricata + n8n | `192.168.64.10` |
| Windows 10 | Endpoint — Sysmon + agente Wazuh | `192.168.64.142` |
| Kali Linux | Atacante — Impacket | `192.168.64.128` |

Recursos mínimos recomendados para la VM Ubuntu: 4 núcleos / 8-12 GB RAM (corre el stack completo de Wazuh + Suricata + n8n).

---

## 2. VM Ubuntu — Wazuh Manager (Docker, single-node)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose git
sudo systemctl enable --now docker

git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.7
cd wazuh-docker/single-node
sudo docker-compose up -d
```

Esto levanta tres contenedores: `wazuh.manager`, `wazuh.indexer` (puerto `9200`) y `wazuh.dashboard` (puerto `443`, HTTPS). Accedé al dashboard en `https://<IP-de-la-VM>` con las credenciales por defecto del `docker-compose.yml` oficial (cambialas si el lab va a quedar expuesto más allá de tu red local).

---

## 3. VM Windows 10 — Endpoint

**3.1. Instalar Sysmon** (telemetría detallada de procesos, red, archivos):

1. Descargá Sysmon desde [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon).
2. Usá una configuración curada — este lab usa la de [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) / [Olaf Hartong](https://github.com/olafhartong/sysmon-modular).
3. Instalar:
   ```powershell
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

**3.2. Instalar el agente de Wazuh:**

1. Descargá el instalador MSI del agente (versión que coincida con el manager, 4.14.7) desde la [documentación oficial de Wazuh](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html).
2. Instalar apuntando al manager:
   ```powershell
   msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<IP-de-la-VM-Ubuntu>"
   ```
3. Iniciar el servicio:
   ```powershell
   NET START WazuhSvc
   ```
4. En el `ossec.conf` del agente, agregar los canales de Windows Event Log que trae Sysmon (`Microsoft-Windows-Sysmon/Operational`) si no vienen por defecto, y reiniciar el servicio.
5. Confirmar en el Dashboard de Wazuh (`Endpoints`) que el agente aparece como `active`.

**3.3. Atomic Red Team** (para simular las técnicas MITRE ATT&CK):

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

---

## 4. VM Kali Linux — Atacante

```bash
sudo apt update && sudo apt install -y python3-pip
pip3 install impacket
```

Verificar conectividad contra el Windows (SMB/WMI según el ataque a simular):
```bash
nmap -p 445,135 <IP-del-Windows>
```

Recordá que en el Windows puede ser necesario:
- Deshabilitar `LocalAccountTokenFilterPolicy` (para permitir PsExec con cuentas locales vía SMB).
- Habilitar el grupo de firewall "Instrumental de administración de Windows (WMI)" para `wmiexec`.

---

## 5. VM Ubuntu — Suricata (NIDS)

```bash
sudo apt update && sudo apt install -y suricata
```

Editar `/etc/suricata/suricata.yaml`:
- `HOME_NET`: la subred del lab (ej. `192.168.64.0/24`)
- `af-packet` → `interface`: la interfaz real de la VM (`ip a` para confirmarla)
- `threads: 1` si la VM tiene pocos núcleos

Copiar las reglas custom del repo a la ubicación de Suricata:
```bash
sudo cp detections/suricata-nids/local.rules /var/lib/suricata/rules/local.rules
```

En `suricata.yaml`, bajo `rule-files`, dejar **solo** la entrada de `local.rules` (si el `suricata-update` oficial no se corrió, no incluir `suricata.rules` — esa entrada apunta a un archivo que no existe y hace que Suricata no cargue ninguna regla).

Habilitar como servicio persistente:
```bash
sudo systemctl enable --now suricata
sudo systemctl status suricata
```

Validar que las reglas cargaron sin errores:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

---

## 6. VM Ubuntu — Reglas custom de Wazuh/Sysmon

Copiar el archivo consolidado y validado al contenedor del manager:
```bash
sudo docker cp detections/sysmon-rules/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
sudo docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml
sudo docker restart single-node-wazuh.manager-1
```

Confirmar que el manager cargó las reglas sin errores:
```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

---

## 7. VM Ubuntu — Integrar Suricata con Wazuh (agente nativo)

Suricata corre en el mismo host que el manager, pero en el host (no en el contenedor), así que hace falta un **agente de Wazuh nativo en el host** apuntando al manager en `127.0.0.1`:

```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.7-1_amd64.deb
sudo WAZUH_MANAGER='127.0.0.1' dpkg -i wazuh-agent.deb
```

En `/var/ossec/etc/ossec.conf` del agente, agregar:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

```bash
sudo systemctl enable --now wazuh-agent
```

Las alertas de Suricata van a aparecer en Wazuh con `rule.id: 86601` (decoder nativo de Suricata), sin necesidad de reglas custom adicionales.

---

## 8. VM Ubuntu — Pipeline n8n + Telegram

Instrucciones completas (incluye habilitar `sqlite3` en n8n, crear la base de deduplicación, y configurar el bot de Telegram) en [`n8n-workflows/README-reproducir-pipeline.md`](../n8n-workflows/README-reproducir-pipeline.md).

---

## 9. Validación end-to-end

1. Ejecutar un Atomic Test en el Windows (ej. `Invoke-AtomicTest T1059.001`).
2. Confirmar la alerta en el Dashboard de Wazuh (`Threat Hunting` o `Discover`).
3. Generar tráfico de red que dispare una regla de Suricata (ej. descarga de un `.exe` por HTTP) y confirmar que aparece como alerta `rule.id: 86601` en Wazuh.
4. Esperar al próximo ciclo del `Schedule Trigger` de n8n (o ejecutarlo manualmente) y confirmar que la alerta llega al bot de Telegram con el enriquecimiento de VirusTotal.
