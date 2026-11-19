#!/usr/bin/env bash
set -e


echo " Этап 1: Сбор данных (OSV + PyPI), потоковая передача в Kafka и HDFS"
echo "================================================================="
source .venv/bin/activate || source .venv/Scripts/activate
python scripts/run_ingestion.py

echo " Этап 2: Расчет Time-to-Fix, кластеризация K-Means и Random Forest"
echo "================================================================="
docker exec bigdata-spark /opt/spark/bin/spark-submit /app/scripts/spark_analytics.py

echo " Этап 3: Проверка стат. гипотез (SciPy) и загрузка в Elasticsearch"
echo "================================================================="
python scripts/hypotheses_and_elastic.py

echo " Конвейер завершен! Дашборд доступен: http://localhost:5601"
echo "================================================================="
