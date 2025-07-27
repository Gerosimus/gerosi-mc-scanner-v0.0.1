import asyncio
import ipaddress
import os
import socket
import re
import json
from datetime import datetime
from typing import List, Dict, Tuple

from colorama import Fore, Style, init
from mcstatus.server import JavaServer
import requests

init(autoreset=True)

COLORS = {
    "ip": Fore.CYAN,
    "version": Fore.GREEN,
    "players": Fore.YELLOW,
    "platform": Fore.MAGENTA,
    "ping": Fore.WHITE,
    "mods": Fore.LIGHTBLUE_EX,
    "error": Fore.RED,
    "whitelist_on": Fore.RED,
    "whitelist_off": Fore.GREEN,
    "country": Fore.LIGHTCYAN_EX,
}

LOG_FILE = "gerosi_scan_errors.log"
COLUMN_WIDTHS = {
    "ip": 25,
    "version": 10,
    "players": 10,
    "platform": 20,
    "ping": 8,
    "mods": 10,
    "whitelist": 12,
    "country": 15,
}

COUNTRY_NAMES = {
    "RU": "Russia",
    "KZ": "Kazakhstan",
    "UA": "Ukraine",
    "BY": "Belarus",
    "US": "USA",
    "DE": "Germany",
    "CN": "China",
    "??": "Unknown",
}


def log_error(target: str, error: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {target} | {error}\n")


def validate_target(target: str) -> bool:
    try:
        address = target.split(":")[0]
        ipaddress.ip_address(address)
        return True
    except ValueError:
        try:
            socket.gethostbyname(address)
            return True
        except socket.gaierror:
            return False


def generate_targets(input_str: str) -> List[str]:
    targets = []

    if os.path.isfile(input_str):
        with open(input_str, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and validate_target(line):
                    if ":" not in line:
                        line += ":25565"
                    targets.append(line)
        return targets

    if "/" in input_str:
        try:
            network = ipaddress.ip_network(input_str, strict=False)
            return [f"{host}:25565" for host in network.hosts()]
        except ValueError:
            return []

    if "-" in input_str:
        try:
            start, end = input_str.split("-", 1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            return [
                f"{ip}:25565"
                for ip in ipaddress.summarize_address_range(start_ip, end_ip)
            ]
        except Exception:
            return []

    if validate_target(input_str):
        if ":" not in input_str:
            return [f"{input_str}:25565"]
        return [input_str]

    return []


def detect_platform(raw_data: dict) -> Tuple[str, str]:
    platform, version = "Unknown", ""
    try:
        version_name = raw_data.get("version", {}).get("name", "").lower()

        if "optifine" in version_name:
            platform = "Optifine"
            optifine_ver = re.search(r"optifine_?(\w+)", version_name)
            version = optifine_ver.group(1)[:8] if optifine_ver else "?"
        elif "forge" in version_name or "forgeData" in raw_data:
            platform = "Forge"
            version = raw_data.get("forgeData", {}).get("forgeVersion", "?")[:10]
        elif "fabric" in version_name:
            platform = "Fabric"
            parts = version_name.split("-")
            if len(parts) > 1 and "fabric" in parts[0]:
                version = parts[1]
        elif "quilt" in version_name:
            platform = "Quilt"
            parts = version_name.split("-")
            if len(parts) > 1:
                version = parts[-1][:10]
        elif "paper" in version_name:
            platform = "Paper"
            version = version_name.split("-")[-1][:8]
        elif "spigot" in version_name:
            platform = "Spigot"
            version = version_name.split("-")[-1][:8]
        elif "bukkit" in version_name:
            platform = "Bukkit"
            version = version_name.split("-")[-1][:8]
        elif "vanilla" in version_name:
            platform = "Vanilla"
            version = version_name.split("-")[0]
        elif "mod" in version_name:
            platform = "Modded"
            version = version_name.split("-")[0]
    except Exception:
        pass

    return platform, version

def get_country_by_ip(ip: str) -> str:
    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') == 'success':
            return data.get('countryCode', '??')
        else:
            return '??'
            
    except requests.exceptions.RequestException:
        return "??"
    except ValueError:
        return "??"


async def scan_server(target: str) -> Dict:
    result = {"target": target, "status": "error", "whitelist": "?"}
    try:
        ip_address = target.split(":")[0]
        country_code = detect_country(ip_address)
        country_name = COUNTRY_NAMES.get(country_code, f"Unknown ({country_code})")

        server = await JavaServer.async_lookup(target, timeout=5)
        status = await server.async_status()
        raw = getattr(status, "raw", {}) or {}

        version = "Unknown"
        if hasattr(status, "version") and status.version:
            version_parts = status.version.name.split()
            for part in version_parts:
                if part.count(".") >= 1 and part[0].isdigit():
                    version = part
                    break

        players = status.players.online if status.players else 0
        max_players = status.players.max if status.players else 0
        platform, platform_ver = detect_platform(raw)

        platform_display = f"{platform} {platform_ver}".strip()
        if not platform_ver:
            platform_display = platform

        mods = []
        mods_count = 0
        if "modinfo" in raw:
            mods = [
                mod.get("modid", "?")[:12]
                for mod in raw["modinfo"].get("modList", [])[:3]
            ]
            mods_count = len(raw["modinfo"].get("modList", []))

        whitelist = False
        motd = str(status.description).lower()
        if "whitelist" in motd or "white-list" in motd:
            whitelist = True

        result.update(
            {
                "status": "success",
                "version": version,
                "players": players,
                "max_players": max_players,
                "platform": platform_display,
                "ping": int(status.latency),
                "mods_count": mods_count,
                "mods": mods,
                "whitelist": whitelist,
                "country": country_name,
                "country_code": country_code,
            }
        )

    except Exception as e:
        error_msg = str(e)
        if "socket.send()" in error_msg or "send()" in error_msg:
            error_msg = "Network error"
        else:
            error_msg = re.sub(r".*Exception: ", "", error_msg)
            error_msg = error_msg.split("\n")[0][:50]

        result["error"] = error_msg

    return result


def format_column(text: str, width: int, color: str = "") -> str:
    text = str(text)[:width]
    return f"{color}{text.ljust(width)}"


def print_server_line(server: Dict):
    if server["status"] != "success":
        log_error(server["target"], server.get("error", "Unknown error"))
        return

    whitelist_color = (
        COLORS["whitelist_on"] if server["whitelist"] else COLORS["whitelist_off"]
    )
    whitelist_text = "Whitelist ON" if server["whitelist"] else "Whitelist OFF"

    columns = [
        format_column(server["target"], COLUMN_WIDTHS["ip"], COLORS["ip"]),
        format_column(server["version"], COLUMN_WIDTHS["version"], COLORS["version"]),
        format_column(
            f"{server['players']}/{server['max_players']}",
            COLUMN_WIDTHS["players"],
            COLORS["players"],
        ),
        format_column(
            server["platform"], COLUMN_WIDTHS["platform"], COLORS["platform"]
        ),
        format_column(f"{server['ping']}ms", COLUMN_WIDTHS["ping"], COLORS["ping"]),
        format_column(
            f"{server['mods_count']} mods", COLUMN_WIDTHS["mods"], COLORS["mods"]
        ),
        format_column(whitelist_text, COLUMN_WIDTHS["whitelist"], whitelist_color),
        format_column(server["country"], COLUMN_WIDTHS["country"], COLORS["country"]),
    ]

    print(" | ".join(columns))


async def main():
    print(f"{Fore.CYAN}Gerosi Minecraft Scanner v0.0.1")
    print(
        f"{Fore.LIGHTBLACK_EX}Примеры: 192.168.1.1 | play.example.com | servers.txt | 10.0.0.0/24"
    )

    targets = []
    while not targets:
        input_str = input(f"{Fore.YELLOW}Введите цели: ").strip()
        targets = generate_targets(input_str)
        if not targets:
            print(f"{COLORS['error']}Нет валидных целей!")

    print(f"\n{Fore.GREEN}Сканируем {len(targets)} серверов...\n")

    headers = [
        format_column("IP", COLUMN_WIDTHS["ip"], Fore.CYAN),
        format_column("Version", COLUMN_WIDTHS["version"], Fore.GREEN),
        format_column("Players", COLUMN_WIDTHS["players"], Fore.YELLOW),
        format_column("Platform", COLUMN_WIDTHS["platform"], Fore.MAGENTA),
        format_column("Ping", COLUMN_WIDTHS["ping"], Fore.WHITE),
        format_column("Mods", COLUMN_WIDTHS["mods"], Fore.LIGHTBLUE_EX),
        format_column("Whitelist", COLUMN_WIDTHS["whitelist"], Fore.WHITE),
        format_column("Country", COLUMN_WIDTHS["country"], Fore.LIGHTCYAN_EX),
    ]
    header_line = " | ".join(headers)
    print(header_line)
    print("-" * len(header_line))

    results = await asyncio.gather(*[scan_server(t) for t in targets])

    successful_servers = [s for s in results if s["status"] == "success"]

    print(f"\n{Fore.CYAN}Сортировать по:")
    print("1. Игрокам (по убыванию)")
    print("2. Игрокам (по возрастанию)")
    print("3. Ping (по убыванию)")
    print("4. Ping (по возрастанию)")
    print("5. Количеству модов")
    print("6. Версии Minecraft")
    print("7. Стране")

    choice = input(f"{Fore.YELLOW}Выберите вариант сортировки (1-7): ")

    if choice == "1":
        successful_servers.sort(key=lambda x: x["players"], reverse=True)
    elif choice == "2":
        successful_servers.sort(key=lambda x: x["players"])
    elif choice == "3":
        successful_servers.sort(key=lambda x: x["ping"], reverse=True)
    elif choice == "4":
        successful_servers.sort(key=lambda x: x["ping"])
    elif choice == "5":
        successful_servers.sort(key=lambda x: x["mods_count"], reverse=True)
    elif choice == "6":
        successful_servers.sort(
            key=lambda x: (
                tuple(map(int, x["version"].split(".")))
                if x["version"] != "Unknown"
                else (0, 0, 0)
            )
        )
    elif choice == "7":
        successful_servers.sort(key=lambda x: x["country"])

    for server in successful_servers:
        print_server_line(server)

    errors = len(results) - len(successful_servers)
    print(f"\n{Fore.GREEN}Успешно: {len(successful_servers)}")
    print(f"{Fore.RED}Ошибки: {errors}")
    if errors > 0:
        print(f"{Fore.LIGHTBLACK_EX}Подробности ошибок в файле: {LOG_FILE}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Программа завершена")
