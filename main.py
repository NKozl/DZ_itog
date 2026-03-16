import json
import os
from collections import Counter
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import requests

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"
LOG_FILE = DATA_DIR / "alerts-only.json"
REPORT_FILE = OUTPUT_DIR / "report.json"
CHART_FILE = OUTPUT_DIR / "top_source_ip.png"
VULNERS_FILE = OUTPUT_DIR / "report_vulners.json"

# Cобытие считаем подозрительным, если severity <= 2
SUSPICIOUS_SEVERITY_LEVELS = {1, 2}
BLOCK_THRESHOLD = 3
VULNERS_URL = "https://vulners.com/api/v3/search/lucene"
VULNERS_QUERIES = [
    "Fortinet AND type:cve order:published",
    "Apache Tomcat AND type:cve order:published",
    "OpenSSH AND type:cve order:published",
]


def ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)



def load_suricata_logs(file_path: Path) -> list:
    """Загрузка JSON-массива с логами Suricata"""
    if not file_path.exists():
        raise FileNotFoundError(f"Файл с логами не найден: {file_path}")

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)



def records_to_dataframe(records: list) -> pd.DataFrame:
    """Преобразование списка JSON-объектов в таблицу pandas"""
    rows = []

    for item in records:
        alert = item.get("alert", {})
        http = item.get("http", {})

        rows.append(
            {
                "timestamp": item.get("timestamp"),
                "event_type": item.get("event_type"),
                "src_ip": item.get("src_ip"),
                "src_port": item.get("src_port"),
                "dest_ip": item.get("dest_ip"),
                "dest_port": item.get("dest_port"),
                "proto": item.get("proto"),
                "severity": alert.get("severity"),
                "category": alert.get("category"),
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "action": alert.get("action"),
                "http_method": http.get("http_method"),
                "hostname": http.get("hostname"),
                "url": http.get("url"),
            }
        )

    return pd.DataFrame(rows)



def is_external_ip(ip_value: str) -> bool:
    """Проверка IP на принадлежность к приватной сети"""
    try:
        return not ip_address(ip_value).is_private
    except ValueError:
        return False



def analyze_suricata_logs(df: pd.DataFrame) -> tuple[dict, pd.DataFrame]:
    """Статистика по логам и подозрительным событиям"""
    suspicious_df = df[df["severity"].isin(SUSPICIOUS_SEVERITY_LEVELS)].copy()

    top_src_counter = Counter(suspicious_df["src_ip"].dropna())
    top_source_ips = [
        {"src_ip": ip, "count": count}
        for ip, count in top_src_counter.most_common(5)
    ]

    category_counts = (
        df["category"].fillna("Не указано").value_counts().head(5).to_dict()
    )
    severity_counts = (
        df["severity"].fillna("Не указано").astype(str).value_counts().to_dict()
    )
    protocol_counts = df["proto"].fillna("Не указано").value_counts().to_dict()

    example_events = []
    for _, row in suspicious_df.head(5).iterrows():
        example_events.append(
            {
                "timestamp": row["timestamp"],
                "src_ip": row["src_ip"],
                "dest_ip": row["dest_ip"],
                "dest_port": int(row["dest_port"]) if pd.notna(row["dest_port"]) else None,
                "severity": int(row["severity"]) if pd.notna(row["severity"]) else None,
                "category": row["category"],
                "signature": row["signature"],
                "http_method": row["http_method"],
                "url": row["url"],
            }
        )

    suricata_report = {
        "source_file": str(LOG_FILE.relative_to(BASE_DIR)),
        "filter_rule": "Событие считается подозрительным, если поле alert.severity равно 1 или 2.",
        "total_events": int(len(df)),
        "suspicious_events": int(len(suspicious_df)),
        "unique_source_ips": int(df["src_ip"].nunique()),
        "unique_destination_ips": int(df["dest_ip"].nunique()),
        "severity_distribution": severity_counts,
        "category_distribution_top5": category_counts,
        "protocol_distribution": protocol_counts,
        "top_source_ips_top5": top_source_ips,
        "example_events": example_events,
    }

    return suricata_report, suspicious_df



def simulate_response(suspicious_df: pd.DataFrame) -> dict:
    """Имитация блокировки внешних IP с частыми событиями"""
    ip_counts = suspicious_df["src_ip"].value_counts()

    blocked_ips = []
    for src_ip, count in ip_counts.items():
        if count >= BLOCK_THRESHOLD and is_external_ip(src_ip):
            blocked_ips.append(
                {
                    "src_ip": src_ip,
                    "events": int(count),
                    "action": "Блокировка IP",
                }
            )

    messages = []
    if blocked_ips:
        for item in blocked_ips:
            messages.append(
                f"[РЕАГИРОВАНИЕ] Найден подозрительный внешний источник {item['src_ip']} ({item['events']} событий). Выполнена блокировка IP."
            )
    else:
        messages.append(
            "[РЕАГИРОВАНИЕ] IP для блокировки не найдены."
        )

    return {
        "rule": f"Если внешний IP встречается в подозрительных событиях {BLOCK_THRESHOLD} раза и более, выводится сообщение об блокировке.",
        "blocked_ips": blocked_ips,
        "messages": messages,
    }



def extract_vulners_results(response_json: dict) -> list:
    """Результаты из ответа API"""
    if isinstance(response_json, dict):
        if isinstance(response_json.get("results"), list):
            return response_json["results"]

        data = response_json.get("data", {})
        if isinstance(data, dict):
            if isinstance(data.get("results"), list):
                return data["results"]
            if isinstance(data.get("search"), list):
                return data["search"]
            if isinstance(data.get("documents"), dict):
                return list(data["documents"].values())
            if isinstance(data.get("documents"), list):
                return data["documents"]

    return []



def first_value(value):
    """Первое значение, если поле пришло списком"""
    if isinstance(value, list):
        return value[0] if value else None
    return value



def normalize_vulners_item(item: dict) -> dict:
    """Результат Vulners"""
    if not isinstance(item, dict):
        return {
            "id": None,
            "title": None,
            "published": None,
            "type": None,
            "cvelist": [],
            "href": None,
            "description": None,
        }

    doc = item

    if isinstance(item.get("_source"), dict):
        doc = item["_source"]
    elif isinstance(item.get("document"), dict):
        doc = item["document"]
    elif isinstance(item.get("fields"), dict):
        doc = item["fields"]

    description = (
        first_value(doc.get("description"))
        or first_value(doc.get("short_description"))
        or first_value(doc.get("flatDescription"))
    )

    cvelist = doc.get("cvelist", [])
    if isinstance(cvelist, str):
        cvelist = [cvelist]
    elif not isinstance(cvelist, list):
        cvelist = []

    return {
        "id": first_value(doc.get("id")) or item.get("_id") or item.get("id"),
        "title": first_value(doc.get("title")),
        "published": first_value(doc.get("published")),
        "type": first_value(doc.get("type")) or first_value(doc.get("bulletinFamily")),
        "cvelist": cvelist,
        "href": first_value(doc.get("href")) or first_value(doc.get("sourceHref")),
        "description": description,
    }



def query_vulners_api() -> dict:
    """Запросы к Vulners API"""
    api_key = os.getenv("VULNERS_API_KEY")

    if not api_key:
        return {
            "status": "skipped",
            "message": "Переменная окружения VULNERS_API_KEY не задана. API-часть пропущена",
            "queries": [],
            "samples": [],
        }

    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
    }

    query_results = []
    samples = []

    for query_text in VULNERS_QUERIES:
        payload = {
            "query": query_text,
            "skip": 0,
            "size": 3,
            "fields": [
                "id",
                "title",
                "published",
                "type",
                "cvelist",
                "description",
                "href",
            ],
        }

        try:
            response = requests.post(
                VULNERS_URL,
                headers=headers,
                json=payload,
                timeout=20,
            )
            response.raise_for_status()
            response_json = response.json()
        except requests.RequestException as error:
            query_results.append(
                {
                    "query": query_text,
                    "status": "error",
                    "message": str(error),
                }
            )
            continue
        except ValueError:
            query_results.append(
                {
                    "query": query_text,
                    "status": "error",
                    "message": "API вернул ответ, который не удалось разобрать как JSON",
                }
            )
            continue

        results = extract_vulners_results(response_json)
        short_items = []

        for item in results[:3]:
            short_item = normalize_vulners_item(item)

            description = short_item.get("description")
            if isinstance(description, str) and len(description) > 200:
                short_item["description"] = description[:200] + "..."

            short_items.append(short_item)
            samples.append(short_item)

        query_results.append(
            {
                "query": query_text,
                "status": "ok",
                "items_found": len(results),
                "items_saved": len(short_items),
                "items": short_items,
            }
        )

    return {
        "status": "ok",
        "message": "Запросы к Vulners API выполнены",
        "queries": query_results,
        "samples": samples,
    }



def save_vulners_samples(vulners_data: dict) -> None:
    with open(VULNERS_FILE, "w", encoding="utf-8") as file:
        json.dump(vulners_data, file, indent=2, ensure_ascii=False)



def save_chart(suspicious_df: pd.DataFrame) -> None:
    """График: топ-5 внешних источников по подозрительным событиям"""
    top_ips = suspicious_df["src_ip"].value_counts().head(5)

    plt.figure(figsize=(8, 5))
    top_ips.plot(kind="bar")
    plt.title("Топ-5 внешних source IP по подозрительным событиям")
    plt.xlabel("Source IP")
    plt.ylabel("Количество событий")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(CHART_FILE)
    plt.close()



def save_report(report: dict) -> None:
    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)



def main() -> None:
    print("Запуск")
    ensure_output_dir()

    try:
        records = load_suricata_logs(LOG_FILE)
    except FileNotFoundError as error:
        print(f"Ошибка: {error}")
        return

    df = records_to_dataframe(records)
    suricata_report, suspicious_df = analyze_suricata_logs(df)
    reaction_report = simulate_response(suspicious_df)
    vulners_report = query_vulners_api()

    report = {
        "project_name": "Мониторинг и реагирование на угрозы",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "suricata_analysis": suricata_report,
        "response_simulation": reaction_report,
        "vulners_api": vulners_report,
        "output_files": {
            "report": str(REPORT_FILE.relative_to(BASE_DIR)),
            "chart": str(CHART_FILE.relative_to(BASE_DIR)),
            "vulners_samples": str(VULNERS_FILE.relative_to(BASE_DIR)),
        },
    }

    save_chart(suspicious_df)
    save_report(report)
    save_vulners_samples(vulners_report)

    print(f"Всего событий в логах: {len(df)}")
    print(f"Подозрительных событий: {len(suspicious_df)}")
    print()

    for message in reaction_report["messages"]:
        print(message)

    print()
    if vulners_report["status"] == "skipped":
        print(vulners_report["message"])
    else:
        print("Vulners API: данные сохранены в outputs/report_vulners.json")

    print(f"Отчёт сохранён: {REPORT_FILE}")
    print(f"График сохранён: {CHART_FILE}")


if __name__ == "__main__":
    main()
