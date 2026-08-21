#!/usr/bin/env python3
"""
vt_lookup.py - Consulta de reputacion de hashes via VirusTotal API v3
AI-Augmented Enterprise Threat Hunting Lab

Uso:
    export VT_API_KEY="tu-api-key"
    python3 vt_lookup.py <hash_md5_sha1_o_sha256>

Diseñado como prototipo standalone: la misma logica de consulta
se reutiliza mas adelante como nodo HTTP Request dentro de n8n.
"""

import os
import sys
import requests

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"


def consultar_hash(hash_valor: str) -> None:
    if not VT_API_KEY:
        print("ERROR: no se encontro la variable de entorno VT_API_KEY.")
        print("Corre: export VT_API_KEY='tu-api-key' antes de ejecutar este script.")
        sys.exit(1)

    headers = {"x-apikey": VT_API_KEY}

    try:
        respuesta = requests.get(f"{VT_BASE_URL}{hash_valor}", headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"ERROR de conexion con la API de VirusTotal: {e}")
        sys.exit(1)

    if respuesta.status_code == 404:
        print(f"[SIN REGISTRO] El hash {hash_valor} no existe en la base de VirusTotal.")
        print("Esto puede indicar un archivo muy nuevo, unico, o generado dinamicamente")
        print("(por ejemplo, binarios con nombre aleatorio de herramientas de post-explotacion).")
        return

    if respuesta.status_code == 401:
        print("ERROR: API key invalida o expirada.")
        sys.exit(1)

    if respuesta.status_code != 200:
        print(f"ERROR inesperado: HTTP {respuesta.status_code}")
        print(respuesta.text[:300])
        sys.exit(1)

    datos = respuesta.json()
    attrs = datos.get("data", {}).get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    maliciosos = stats.get("malicious", 0)
    sospechosos = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    nombres = attrs.get("names", [])
    tipo = attrs.get("type_description", "Desconocido")
    tamano = attrs.get("size", "N/A")
    primera_vez = attrs.get("first_submission_date", "N/A")
    reputacion = attrs.get("reputation", "N/A")

    print("=" * 60)
    print(f"Hash consultado:      {hash_valor}")
    print(f"Tipo de archivo:      {tipo}")
    print(f"Tamano:               {tamano} bytes")
    print(f"Nombres conocidos:    {', '.join(nombres[:5]) if nombres else 'N/A'}")
    print(f"Reputacion VT:        {reputacion}")
    print("-" * 60)
    print(f"Deteccion:            {maliciosos} maliciosos / {sospechosos} sospechosos / {total} motores")

    if maliciosos == 0 and sospechosos == 0:
        print("VEREDICTO:            LIMPIO - sin detecciones")
    elif maliciosos >= 5:
        print("VEREDICTO:            MALICIOSO - alta confianza")
    else:
        print("VEREDICTO:            REVISAR - detecciones bajas, posible falso positivo o amenaza nueva")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 vt_lookup.py <hash>")
        sys.exit(1)

    consultar_hash(sys.argv[1].strip())
