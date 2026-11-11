# Cómo reproducir este pipeline (n8n + Telegram)

Este workflow consulta periódicamente el Indexer de Wazuh, enriquece cada alerta con VirusTotal, filtra duplicados con una base SQLite local, y envía una notificación formateada a un bot de Telegram.

## 1. Importar el workflow

1. Abrí n8n → **Workflows** → **Import from File** → seleccioná `soc-n8n-workflow.json`.
2. El workflow se importa con todos los nodos, pero **sin credenciales** (no se exportan por seguridad) y con placeholders en el nodo de Telegram.

## 2. Recrear las credenciales

### a) Basic Auth — consulta al Indexer de Wazuh
- Nodo **HTTP Request** (el primero, que consulta `wazuh-alerts-*/_search`).
- Credential Type: **Basic Auth**.
- Usuario / contraseña: los de tu Indexer (por defecto en el docker-compose oficial de Wazuh single-node: `admin` / `SecretPassword`, pero cambialo si no estás en un entorno de lab).

### b) Header Auth — VirusTotal
- Nodo **HTTP Request1** (el que consulta `virustotal.com/api/v3/files/{sha256}`).
- Credential Type: **Header Auth**.
- Name: `x-apikey`
- Value: tu API key personal de VirusTotal (gratuita en [virustotal.com](https://www.virustotal.com)).

### c) Bot de Telegram
1. Hablale a **@BotFather** en Telegram → `/newbot` → seguí los pasos → te da un token tipo `123456789:ABC...`.
2. Hablale una vez a tu bot recién creado (cualquier mensaje) para generar un chat.
3. Andá a `https://api.telegram.org/bot<TU_TOKEN>/getUpdates` en el navegador → copiá el `chat.id` que aparece en la respuesta JSON.
4. En el nodo **HTTP Request2** (el último, el que envía a Telegram):
   - Reemplazá `YOUR_TELEGRAM_BOT_TOKEN` en la URL por tu token real.
   - Reemplazá `YOUR_TELEGRAM_CHAT_ID` en el campo JSON Body por tu `chat_id` real.

## 3. Habilitar el módulo `sqlite3` en n8n

Por defecto, n8n bloquea el uso de módulos externos de Node.js (`require`) dentro de los nodos Code. Hay que levantar el contenedor con la variable de entorno `NODE_FUNCTION_ALLOW_EXTERNAL=sqlite3`:

```
sudo docker run -d --name n8n \
  -p 5678:5678 \
  -v ~/n8n-data:/home/node/.n8n \
  -e NODE_FUNCTION_ALLOW_EXTERNAL=sqlite3 \
  docker.n8n.io/n8nio/n8n
```

## 4. Crear la base SQLite de deduplicación

Dentro del host donde corre el contenedor (montando el mismo volumen `~/n8n-data`):

```bash
sudo apt install -y sqlite3
mkdir -p ~/n8n-data/db
sqlite3 ~/n8n-data/db/soc_alerts.db <<'EOF'
CREATE TABLE alertas (
  alerta_id TEXT PRIMARY KEY,
  regla_id TEXT,
  nivel INTEGER,
  descripcion TEXT,
  mitre_id TEXT,
  imagen TEXT,
  sha256 TEXT,
  vt_maliciosos INTEGER,
  vt_sospechosos INTEGER,
  vt_total_motores INTEGER,
  vt_estado TEXT
);
EOF
chmod 666 ~/n8n-data/db/soc_alerts.db
chmod 777 ~/n8n-data/db
```

Esto es necesario porque el pipeline no crea la tabla automáticamente — asume que ya existe.

## 5. Activar el workflow

Una vez configuradas las credenciales y la base, activá el workflow (toggle **Active** arriba a la derecha en n8n). El `Schedule Trigger` corre cada 1 minuto por defecto (configurable en ese nodo).

## Arquitectura del flujo

```
Schedule Trigger
  → HTTP Request (consulta Indexer de Wazuh, Basic Auth)
  → Split Out (una alerta por item)
  → Code in JavaScript (extrae campos relevantes + SHA256 de los hashes)
  → Filter (descarta alertas sin SHA256)
  → Code in JavaScript1 (dedup: descarta alertas ya en SQLite)
  → Loop Over Items
      → HTTP Request1 (VirusTotal, Header Auth)
      → Code in JavaScript2 (inserta/actualiza resultado en SQLite)
      → Code in JavaScript4 (arma el mensaje con formato MarkdownV2)
      → HTTP Request2 (envía a Telegram)
  → Wait (16s entre iteraciones, por rate limit de VirusTotal en API gratuita)
  → vuelve a Loop Over Items
```
