#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import urllib.parse
from tempfile import NamedTemporaryFile

def parse_vless_url(vless_url):
    if not vless_url.startswith("vless://"):
        raise ValueError("Ссылка должна начинаться с vless://")
    url = vless_url[8:]
    if "@" not in url:
        raise ValueError("Неверный формат VLESS-ссылки")
    uuid_part, rest = url.split("@", 1)
    uuid = uuid_part

    if "?" in rest:
        host_port, query = rest.split("?", 1)
    else:
        host_port, query = rest, ""

    if ":" not in host_port:
        raise ValueError("Порт не указан в адресе")
    host, port_str = host_port.rsplit(":", 1)
    port = int(port_str)

    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    def g(k, d=None): return params.get(k, [d])[0]

    return {
        "uuid": uuid,
        "host": host,
        "port": port,
        "security": g("security", "none"),
        "flow": g("flow", ""),
        "fp": g("fp", "chrome"),
        "pbk": g("pbk", ""),
        "sni": g("sni", host),
        "type": g("type", "tcp"),
        "path": g("path", "/"),
        "sid": g("sid", ""),
        "spx": g("spx", ""),
    }

def generate_xray_config(vless_data, local_port=25443):
    # flow не поддерживается в outbound (клиенте)
    user_flow = "" if vless_data.get("flow") in ("xtls-rprx-vision", "xtls-rprx-vision-udp443") else vless_data.get("flow", "")

    config = {
        "log": {"loglevel": "debug"},
        "dns": {
            "servers": ["8.8.8.8", "1.1.1.1"],
            "tag": "dns_out"
        },
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False,
                "ip": "127.0.0.1"
            },
            "tag": "socks-in"
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": vless_data["host"],
                    "port": vless_data["port"],
                    "users": [{
                        "id": vless_data["uuid"],
                        "flow": user_flow,
                        "encryption": "none"
                    }]
                }],
                "domainStrategy": "UseIP"
            },
            "streamSettings": {
                "network": vless_data["type"],
                "security": vless_data["security"],
            },
            "tag": "vless-out"
        }, {
            "protocol": "dns",
            "tag": "dns-out"
        }],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-in"],
                    "network": "udp",
                    "port": 53,
                    "outboundTag": "dns-out"
                }
            ]
        }
    }

    ss = config["outbounds"][0]["streamSettings"]

    if vless_data["security"] == "reality":
        ss["realitySettings"] = {
            "publicKey": vless_data["pbk"],
            "shortId": vless_data["sid"],
            "fingerprint": vless_data["fp"],
            "serverName": vless_data["sni"],
            "spiderX": vless_data["spx"]
        }
    elif vless_data["security"] == "tls":
        ss["tlsSettings"] = {
            "serverName": vless_data["sni"],
            "fingerprint": vless_data["fp"]
        }

    if vless_data["type"] == "ws":
        ss["wsSettings"] = {"path": vless_data["path"]}

    return config

def main():
    if len(sys.argv) != 2:
        print("Использование: КАВЫЧКИ vless://.... КАВЫЧКИ")
        print("Прокси: socks5://127.0.0.1:25443")
        sys.exit(1)

    vless_url = sys.argv[1]

    try:
        data = parse_vless_url(vless_url)
        config = generate_xray_config(data, local_port=25443)
    except Exception as e:
        print(f"[!] Ошибка: {e}")
        sys.exit(1)

    with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        cfg_path = f.name

    print(f"[+] Запуск Xray... ПРЕДУПРЕЖДЕНИЕ!!!! ЗАПУСКАТЬ С КАВЫЧКАМИ ПО ПРИМЕРУ python3 startobhod.py КАВЫЧКИ vless://.... КАВЫЧКИ")
    print(f"[+] ЕСЛИ ЗАПУСКАТЬ НЕ ТАК ТО ЯДРО НЕ ПОЙМЁТ ЧТО ОТ НЕГО ХОТЯТ ")
    print(f"[+] Socks5-прокси: 127.0.0.1:25443")
    print(f"[+] Сервер: {data['host']}:{data['port']} | Тип: {data['type']} | Безопасность: {data['security']}")

    try:
        result = subprocess.run(["xray", "run", "-config", cfg_path])
    finally:
        os.unlink(cfg_path)

if __name__ == "__main__":
    main()
