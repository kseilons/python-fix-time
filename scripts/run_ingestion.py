import json
import os
import time
import pandas as pd
from kafka import KafkaProducer, KafkaConsumer
from hdfs import InsecureClient

from ttf_pipeline.clients.osv_client import download_osv_archive, extract_osv_archive
from ttf_pipeline.parsers.osv_parser import parse_osv_directory
from ttf_pipeline.clients.pypi_client import PyPIClient
from ttf_pipeline.config import DATA_RAW_DIR, OSV_PARQUET_PATH, OSV_RAW_DIR, OSV_ZIP_PATH

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "vuln-raw-stream"
HDFS_URL = "http://localhost:9870"
HDFS_DIR = "/bigdata/raw"


def get_dir_size_mb(path):
    total = 0
    if not os.path.exists(path):
        return 0.0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total / (1024 * 1024)


def main():
    metrics = []
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Скачивание и парсинг OSV
    print("\n--- [1/4] Сбор данных из OSV ---")
    t0 = time.time()
    if not OSV_ZIP_PATH.exists():
        download_osv_archive()
    if not OSV_RAW_DIR.exists() or not any(OSV_RAW_DIR.glob("*.json")):
        extract_osv_archive()
    osv_df = parse_osv_directory(OSV_RAW_DIR)
    osv_df.to_parquet(OSV_PARQUET_PATH, index=False)
    t_osv = time.time() - t0
    osv_size = get_dir_size_mb(OSV_RAW_DIR)
    metrics.append(("1. Загрузка и парсинг OSV", len(osv_df), osv_size, t_osv))

    # 2. Сбор релизов из PyPI API
    print("\n--- [2/4] Сбор истории релизов из PyPI API ---")
    t0 = time.time()
    packages = sorted(osv_df["package_name"].dropna().unique().tolist())
    client = PyPIClient(delay=0.05)
    client.fetch_all(packages)
    pypi_cache = client.load_cached_releases_map()
    t_pypi = time.time() - t0
    pypi_size = get_dir_size_mb(DATA_RAW_DIR / "pypi_releases")
    metrics.append(("2. Сбор метаданных PyPI API", len(pypi_cache), pypi_size, t_pypi))

    # 3. Отправка потока данных в Apache Kafka (Producer)
    print("\n--- [3/4] Потоковая отправка в Apache Kafka ---")
    t0 = time.time()
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
    )

    records = osv_df.to_dict(orient="records")
    sent_count = 0
    for rec in records:
        pkg = str(rec.get("package_name", "")).lower()
        rec["pypi_releases"] = pypi_cache.get(pkg, {})
        producer.send(KAFKA_TOPIC, value=rec)
        sent_count += 1

    producer.flush()
    producer.close()
    t_kafka_pub = time.time() - t0
    total_raw_size = osv_size + pypi_size
    metrics.append(("3. Отправка в Kafka (Producer)", sent_count, total_raw_size, t_kafka_pub))

    # 4. Чтение из Kafka (Consumer) и сохранение в Hadoop HDFS
    print("\n--- [4/4] Выгрузка из Kafka в Hadoop HDFS ---")
    t0 = time.time()
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        consumer_timeout_ms=5000,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )

    consumed_records = [msg.value for msg in consumer]
    consumer.close()

    local_dump = DATA_RAW_DIR / "kafka_stream_dump.jsonl"
    with open(local_dump, "w", encoding="utf-8") as f:
        for rec in consumed_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    dump_size_mb = os.path.getsize(local_dump) / (1024 * 1024)

    # Загружаем файл в HDFS через контейнер namenode (избегаем проблем DNS Docker на Windows)
    os.system(f'docker cp "{local_dump}" bigdata-namenode:/tmp/vuln_raw_stream.json')
    os.system(f'docker exec bigdata-namenode hdfs dfs -mkdir -p {HDFS_DIR}')
    os.system(f'docker exec bigdata-namenode hdfs dfs -put -f /tmp/vuln_raw_stream.json {HDFS_DIR}/vuln_raw_stream.json')

    t_hdfs = time.time() - t0
    metrics.append(("4. Запись из Kafka в HDFS", len(consumed_records), dump_size_mb, t_hdfs))

    # Вывод итоговой таблицы замеров 
    print("\n" + "=" * 75)
    print(f"{'Этап конвейера':<32} | {'Записей':<8} | {'Объем (МБ)':<10} | {'Время (с)':<9} | {'Скор. (МБ/с)'}")
    print("-" * 75)
    for name, cnt, sz, tm in metrics:
        speed = sz / tm if tm > 0 else 0
        print(f"{name:<32} | {cnt:<8} | {sz:<10.2f} | {tm:<9.2f} | {speed:.2f}")
    print("=" * 75)

if __name__ == "__main__":
    main()
