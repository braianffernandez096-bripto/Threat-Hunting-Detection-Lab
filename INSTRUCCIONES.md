# Último paso — limpieza final

El repo ya no menciona Snort ni Slack en ningún lado excepto en estos dos archivos (que están pensados como registros puntuales de trabajo ya terminado, no como documentación permanente). Lo más simple es borrarlos directamente del repo vía GitHub:

## Archivos a borrar

- `docs/README-update-nov2026.md` → todo su contenido ya está integrado dentro de la sección "Actualización" del `README.md` principal. Mantenerlo sería tener el mismo texto duplicado en dos lugares, uno de ellos (este) todavía con el lenguaje viejo.
- `INSTRUCCIONES.md` (este archivo, en la raíz) → ya cumplió su función como nota de trabajo puntual. Una vez subido el `README.md` actualizado, no aporta nada que no esté ya reflejado en el repo.
- `docs/screenshots/02-wazuh-agent-registered.png` y `docs/screenshots/03-wazuh-agent-detail-mitre.png` → no están referenciadas en ningún texto del README y son redundantes con `01-wazuh-dashboard-overview.png` (dashboard general) y `04-detection-rule-92071.png` (regla nativa disparando con detalle), que ya cubren ese tipo de muestra visual.

## Archivo a subir

- `README.md` → pisa el actual. Esta versión no tiene ninguna mención a Snort ni a Slack en ningún lado; todo se describe como la implementación actual (Suricata, Telegram).

Con esto, el repo queda sin ningún rastro textual de las tecnologías reemplazadas.
