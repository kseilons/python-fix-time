#!/usr/bin/env bash
set -e

echo " [1/3] Запуск Docker-контейнеров (Kafka, HDFS, Spark, ELK)"
echo "================================================================="
docker compose up -d

echo "Ожидание запуска сервисов (15 сек)..."
sleep 15

echo " [2/3] Настройка виртуального окружения и установка пакетов"
echo "================================================================="
if [ ! -d ".venv" ]; then
    python3 -m venv .venv || python -m venv .venv
fi
source .venv/bin/activate || source .venv/Scripts/activate
pip install -r requirements.txt

echo "Установка numpy для PySpark MLlib в контейнер bigdata-spark..."
pip download numpy --only-binary=:all: --platform manylinux2014_x86_64 --python-version 310 -d data/tmp_wheels
MSYS_NO_PATHCONV=1 docker exec bigdata-spark pip install --no-index --find-links=/app/data/tmp_wheels numpy
rm -rf data/tmp_wheels

echo " [3/3] Проверка работы контейнеров"
echo "================================================================="
docker compose ps
echo "Все сервисы успешно запущены и готовы к работе!"
