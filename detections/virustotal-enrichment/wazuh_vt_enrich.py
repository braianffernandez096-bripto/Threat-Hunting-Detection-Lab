#!/usr/bin/env python3
"""
wazuh_vt_enrich.py - Enriquecimiento automatico de alertas de Wazuh con VirusTotal
AI-Augmented Enterprise Threat Hunting Lab

Consulta el Indexer de Wazuh (OpenSearch) por alertas recientes de nivel alto
que tengan un hash de archivo asociado, y las enriquece con la reputacion
de VirusTotal. Disenado como prototipo: la misma logica se porta despues
a un workflow de n8n (nodo de consulta + nodo de enriquecimiento).

Uso:
    export VT_API_KEY="tu-api-key"
    python3 wazuh_vt_enrich.py
"""

import os
import re
import sys
import json
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VT_API_KEY = os.environ.get("VT_API_KEY")
WAZUH_INDEXER_URL = "https://localhost:9200/wazuh-alerts-*/_search"
WAZUH_USER = "admin"
WAZUH_PASS = "SecretPassword"
NIVEL_MINIMO = 12
PROCESADOS_PATH = os.path.expanduser("~/soc-l2-scripts/.vt_procesados.json")


def cargar_procesados() -> set:
    if os.path.exists(PROCESADOS_PATH):
        with open(PROCESADOS_PATH, "r") as f:
            return set(json.load(f))
    return set()


def guardar_procesados(procesados: set) -> None:
    with open(PROCESADOS_PATH, "w") as f:
        json.dump(list(procesados), f)


def buscar_alertas_recientes() -> list:
    query = {
        "size": 20,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": NIVEL_MINIMO}}},
                    {"exists": {"field": "data.win.eventdata.hashes"}}
                ]
            }
        }
    }
    resp = requests.get(
        WAZUH_INDEXER_URL,
        auth=(WAZUH_USER, WAZUH_PASS),
        headers={"Content-Type": "application/json"},
        data=json.dumps(query),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("hits", {}).get("hits", [])


def extraer_sha256(hashes_str: str):
    match = re.search(r"SHA256=([A-Fa-f0-9]{64})", hashes_str or "")
    return match.group(1) if match else None


def consultar_vt(sha256: str) -> dict:
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 404:
        return {"estado": "sin_registro"}
    resp.raise_for_status()
    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "estado": "ok",
        "maliciosos": stats.get("malicious", 0),
        "sospechosos": stats.get("suspicious", 0),
        "total": sum(stats.values()) if stats else 0,
        "nombres": attrs.get("names", [])[:3],
    }


def main():
    if not VT_API_KEY:
        print("ERROR: falta la variable de entorno VT_API_KEY.")
        sys.exit(1)

    procesados = cargar_procesados()
    hits = buscar_alertas_recientes()

    if not hits:
        print("No hay alertas de nivel >= 12 con hash asociado en este momento.")
        return

    nuevos = 0
    for hit in hits:
        alerta_id = hit["_id"]
        if alerta_id in procesados:
            continue

        src = hit["_source"]
        regla = src.get("rule", {})
        eventdata = src.get("data", {}).get("win", {}).get("eventdata", {})
        hashes_str = eventdata.get("hashes", "")
        sha256 = extraer_sha256(hashes_str)

        print("=" * 70)
        print(f"Alerta:       {regla.get('description', 'N/A')}")
        print(f"Regla ID:     {regla.get('id', 'N/A')}  (nivel {regla.get('level', 'N/A')})")
        print(f"MITRE:        {regla.get('mitre', {}).get('id', ['N/A'])}")
        print(f"Imagen:       {eventdata.get('image', 'N/A')}")

        if not sha256:
            print("Sin hash SHA256 disponible en esta alerta, se omite consulta a VT.")
        else:
            print(f"SHA256:       {sha256}")
            try:
                resultado = consultar_vt(sha256)
                if resultado["estado"] == "sin_registro":
                    print("VirusTotal:   SIN REGISTRO (archivo no visto antes, o generado dinamicamente)")
                else:
                    print(f"VirusTotal:   {resultado['maliciosos']} maliciosos / "
                          f"{resultado['sospechosos']} sospechosos / {resultado['total']} motores")
                    if resultado["nombres"]:
                        print(f"Otros nombres vistos: {', '.join(resultado['nombres'])}")
                time.sleep(16)  # respeta el limite de 4 req/min del tier gratuito
            except requests.exceptions.RequestException as e:
                print(f"Error consultando VirusTotal: {e}")

        procesados.add(alerta_id)
        nuevos += 1

    guardar_procesados(procesados)
    print("=" * 70)
    print(f"Procesadas {nuevos} alertas nuevas.")


if __name__ == "__main__":
    main()
