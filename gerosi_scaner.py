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


def detect_country(ip: str) -> str:
    try:
        octets = ip.split(".")
        if not octets:
            return "??"

        first = int(octets[0])
        second = int(octets[1])

        if (
            (first == 77 and 88 <= second <= 99)
            or (first == 78)
            or (first == 79)
            or (first == 88)
            or (first == 89)
            or (first == 90)
            or (first == 91)
            or (first == 92)
            or (first == 93)
            or (first == 94)
            or (first == 95)
            or (first == 178 and second == 16)
            or (first == 178 and second == 17)
            or (first == 178 and 130 <= second <= 159)
            or (first == 195)
        ):
            return "RU"

        elif (
            (first == 77 and 74 <= second <= 87)
            or (first == 77 and 40 <= second <= 41)
            or (first == 85 and second == 21)
            or (first == 213 and second == 184)
        ):
            return "KZ"

        elif (
            (first == 31 and second == 134)
            or (first == 31 and second == 148)
            or (first == 31 and second == 172)
            or (first == 37 and second == 52)
            or (first == 46 and second == 109)
            or (first == 46 and second == 133)
            or (first == 46 and second == 164)
            or (first == 46 and second == 175)
            or (first == 46 and second == 185)
            or (first == 46 and second == 200)
            or (first == 62 and second == 16)
            or (first == 78 and second == 26)
            or (first == 78 and second == 111)
            or (first == 80 and second == 91)
            or (first == 91 and second == 193)
            or (first == 91 and second == 194)
            or (first == 91 and second == 196)
            or (first == 91 and second == 198)
            or (first == 91 and second == 199)
            or (first == 91 and second == 217)
            or (first == 91 and second == 218)
            or (first == 91 and second == 219)
            or (first == 91 and second == 220)
            or (first == 91 and second == 221)
            or (first == 91 and second == 222)
            or (first == 91 and second == 223)
            or (first == 91 and second == 224)
            or (first == 91 and second == 225)
            or (first == 91 and second == 226)
            or (first == 91 and second == 227)
            or (first == 91 and second == 228)
            or (first == 91 and second == 229)
            or (first == 91 and second == 230)
            or (first == 91 and second == 231)
            or (first == 91 and second == 232)
            or (first == 91 and second == 233)
            or (first == 91 and second == 234)
            or (first == 91 and second == 235)
            or (first == 91 and second == 236)
            or (first == 91 and second == 237)
            or (first == 91 and second == 238)
            or (first == 91 and second == 239)
            or (first == 91 and second == 240)
            or (first == 91 and second == 241)
            or (first == 91 and second == 242)
            or (first == 91 and second == 243)
            or (first == 91 and second == 244)
            or (first == 91 and second == 245)
            or (first == 91 and second == 246)
            or (first == 91 and second == 247)
            or (first == 91 and second == 248)
            or (first == 91 and second == 249)
            or (first == 91 and second == 250)
            or (first == 91 and second == 251)
            or (first == 91 and second == 252)
            or (first == 91 and second == 253)
            or (first == 91 and second == 254)
            or (first == 91 and second == 255)
            or (first == 92 and second == 113)
            or (first == 93 and second == 170)
            or (first == 93 and second == 171)
            or (first == 93 and second == 172)
            or (first == 93 and second == 173)
            or (first == 93 and second == 174)
            or (first == 93 and second == 175)
            or (first == 93 and second == 176)
            or (first == 93 and second == 177)
            or (first == 93 and second == 178)
            or (first == 93 and second == 179)
            or (first == 93 and second == 180)
            or (first == 93 and second == 181)
            or (first == 93 and second == 182)
            or (first == 93 and second == 183)
            or (first == 93 and second == 184)
            or (first == 93 and second == 185)
            or (first == 93 and second == 186)
            or (first == 93 and second == 187)
            or (first == 93 and second == 188)
            or (first == 93 and second == 189)
            or (first == 93 and second == 190)
            or (first == 93 and second == 191)
            or (first == 94 and second == 45)
            or (first == 94 and second == 154)
            or (first == 94 and second == 177)
            or (first == 94 and second == 178)
            or (first == 94 and second == 179)
            or (first == 94 and second == 180)
            or (first == 94 and second == 181)
            or (first == 94 and second == 182)
            or (first == 94 and second == 183)
            or (first == 94 and second == 184)
            or (first == 94 and second == 185)
            or (first == 94 and second == 186)
            or (first == 94 and second == 187)
            or (first == 94 and second == 188)
            or (first == 94 and second == 189)
            or (first == 94 and second == 190)
            or (first == 94 and second == 191)
            or (first == 95 and second == 46)
            or (first == 109 and second == 86)
            or (first == 109 and second == 162)
            or (first == 109 and second == 200)
            or (first == 134 and second == 249)
            or (first == 176 and second == 36)
            or (first == 176 and second == 37)
            or (first == 176 and second == 100)
            or (first == 178 and second == 19)
            or (first == 178 and second == 92)
            or (first == 178 and second == 93)
            or (first == 178 and second == 151)
            or (first == 178 and second == 159)
            or (first == 178 and second == 212)
            or (first == 178 and second == 213)
            or (first == 178 and second == 215)
            or (first == 178 and second == 217)
            or (first == 178 and second == 218)
            or (first == 178 and second == 219)
            or (first == 178 and second == 220)
            or (first == 178 and second == 221)
            or (first == 178 and second == 222)
            or (first == 185 and second == 5)
            or (first == 185 and second == 22)
            or (first == 185 and second == 44)
            or (first == 185 and second == 76)
            or (first == 185 and second == 100)
            or (first == 185 and second == 157)
            or (first == 193 and second == 41)
            or (first == 193 and second == 109)
            or (first == 195 and second == 245)
            or (first == 212 and second == 90)
            or (first == 212 and second == 111)
            or (first == 213 and second == 179)
        ):
            return "UA"

        elif (
            (first == 37 and second == 212)
            or (first == 46 and second == 53)
            or (first == 46 and second == 249)
            or (first == 62 and second == 105)
            or (first == 77 and second == 222)
            or (first == 77 and second == 223)
            or (first == 79 and second == 98)
            or (first == 79 and second == 133)
            or (first == 81 and second == 30)
            or (first == 81 and second == 91)
            or (first == 82 and second == 209)
            or (first == 84 and second == 201)
            or (first == 86 and second == 57)
            or (first == 93 and second == 125)
            or (first == 95 and second == 46)
            or (first == 95 and second == 129)
            or (first == 109 and second == 86)
            or (first == 109 and second == 236)
            or (first == 176 and second == 36)
            or (first == 178 and second == 19)
            or (first == 178 and second == 93)
            or (first == 178 and second == 159)
            or (first == 185 and second == 5)
            or (first == 185 and second == 44)
            or (first == 193 and second == 41)
            or (first == 193 and second == 93)
            or (first == 193 and second == 109)
            or (first == 195 and second == 245)
            or (first == 212 and second == 98)
            or (first == 213 and second == 184)
        ):
            return "BY"

        elif (
            (first == 58)
            or (first == 59)
            or (first == 60)
            or (first == 61)
            or (first == 110)
            or (first == 111)
            or (first == 112)
            or (first == 113)
            or (first == 114)
            or (first == 115)
            or (first == 116)
            or (first == 117)
            or (first == 118)
            or (first == 119)
            or (first == 120)
            or (first == 121)
            or (first == 122)
            or (first == 123)
            or (first == 124)
            or (first == 125)
            or (first == 126)
            or (first == 171)
            or (first == 175)
            or (first == 180)
            or (first == 182)
            or (first == 183)
            or (first == 202)
            or (first == 203)
            or (first == 210)
            or (first == 211)
            or (first == 218)
            or (first == 219)
            or (first == 220)
            or (first == 221)
            or (first == 222)
            or (first == 223)
        ):
            return "CN"

        elif (
            (first == 78)
            or (first == 79)
            or (first == 80)
            or (first == 81)
            or (first == 82)
            or (first == 83)
            or (first == 84)
            or (first == 85)
            or (first == 87)
            or (first == 88)
            or (first == 89)
            or (first == 91)
            or (first == 92)
            or (first == 93)
            or (first == 94)
            or (first == 95)
            or (first == 176)
            or (first == 178)
            or (first == 185)
            or (first == 188)
            or (first == 212)
        ):
            return "DE"

        elif (
            (first == 3)
            or (first == 4)
            or (first == 6)
            or (first == 8)
            or (first == 9)
            or (first == 11)
            or (first == 12)
            or (first == 13)
            or (first == 15)
            or (first == 16)
            or (first == 17)
            or (first == 18)
            or (first == 19)
            or (first == 20)
            or (first == 21)
            or (first == 22)
            or (first == 23)
            or (first == 24)
            or (first == 26)
            or (first == 28)
            or (first == 29)
            or (first == 30)
            or (first == 32)
            or (first == 33)
            or (first == 34)
            or (first == 35)
            or (first == 38)
            or (first == 40)
            or (first == 44)
            or (first == 45)
            or (first == 47)
            or (first == 48)
            or (first == 50)
            or (first == 52)
            or (first == 54)
            or (first == 55)
            or (first == 56)
            or (first == 63)
            or (first == 64)
            or (first == 65)
            or (first == 66)
            or (first == 67)
            or (first == 68)
            or (first == 69)
            or (first == 70)
            or (first == 71)
            or (first == 72)
            or (first == 73)
            or (first == 74)
            or (first == 75)
            or (first == 76)
            or (first == 96)
            or (first == 97)
            or (first == 98)
            or (first == 99)
            or (first == 100)
            or (first == 104)
            or (first == 107)
            or (first == 108)
            or (first == 128)
            or (first == 129)
            or (first == 130)
            or (first == 131)
            or (first == 132)
            or (first == 134)
            or (first == 135)
            or (first == 136)
            or (first == 137)
            or (first == 138)
            or (first == 139)
            or (first == 140)
            or (first == 142)
            or (first == 143)
            or (first == 144)
            or (first == 146)
            or (first == 147)
            or (first == 148)
            or (first == 149)
            or (first == 150)
            or (first == 152)
            or (first == 153)
            or (first == 155)
            or (first == 156)
            or (first == 157)
            or (first == 158)
            or (first == 159)
            or (first == 160)
            or (first == 161)
            or (first == 162)
            or (first == 164)
            or (first == 165)
            or (first == 166)
            or (first == 167)
            or (first == 168)
            or (first == 169)
            or (first == 170)
            or (first == 172)
            or (first == 173)
            or (first == 174)
            or (first == 192)
            or (first == 198)
            or (first == 199)
            or (first == 204)
            or (first == 205)
            or (first == 206)
            or (first == 207)
            or (first == 208)
            or (first == 209)
            or (first == 216)
        ):
            return "US"

        else:
            return "??"
    except:
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
