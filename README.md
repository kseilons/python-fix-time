# Анализ жизненного цикла уязвимостей в PyPI (Time-to-Fix)

Исследование времени устранения уязвимостей (**Time-to-Fix**, TTF) в экосистеме Python на основе открытых данных **OSV** и реестра **PyPI**.

## Источники данных
- [OSV PyPI Dump](https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip)
- [PyPI JSON API](https://pypi.org/pypi/{package}/json)

## Структура репозитория

```text
python-fix-time/
├── data/
│   ├── raw/                        # Дампы OSV и кэш PyPI
│   └── processed/                  # ttf_dataset.parquet, ttf_dataset.csv и ttf_spark_final.json
├── scripts/
│   ├── run_ingestion.py            # Сбор данных и потоковая загрузка
│   ├── spark_analytics.py          # Расчет метрик, агрегации и модели машинного обучения
│   └── hypotheses_and_elastic.py   # Проверка гипотез и загрузка данных в хранилище
├── notebooks/
│   └── data_exploration.ipynb
├── ttf_pipeline/                   # Логика клиентов, парсеров и расчет метрик
├── legacy/                         # Скрипты сбора данных первого этапа
│   ├── fetch_osv.py                # Скачивание и парсинг дампа OSV
│   ├── fetch_pypi.py               # Сбор дат релизов из PyPI API
│   └── build_dataset.py            # Расчет TTF и сборка датасета
├── docker-compose.yml              # Конфигурация контейнеров кластера
├── setup_env.sh                    # Установка зависимостей и подготовка окружения
├── run_pipeline.sh                 # Запуск полного конвейера
├── kibana_dashboard.ndjson         # Конфигурация дашборда Kibana
├── requirements.txt
└── README.md
```

## Быстрый старт

```bash
pip install -r requirements.txt

# Сбор данных
python fetch_osv.py
python fetch_pypi.py
python build_dataset.py

# Анализ
jupyter notebook notebooks/data_exploration.ipynb
```

### Запуск распределенного конвейера 

```bash
# Подготовка окружения и запуск контейнеров
bash setup_env.sh

# Запуск конвейера обработки данных
bash run_pipeline.sh
```

### Импорт дашборда в Kibana

1. Открыть `http://localhost:5601` -> меню слева сверху -> **Management -> Stack Management -> Kibana -> Saved Objects**.
2. Нажать **Import**, выбрать файл `kibana_dashboard.ndjson`, подтвердить загрузку.
3. Перейти в меню -> **Analytics -> Dashboards**, открыть **`PyPI Vulnerability Lifecycle Dashboard`** и выбрать период **Last 15 years** в правом верхнем углу.

## Датасет (`data/processed/ttf_dataset.parquet`)

| Колонка | Описание |
|---|---|
| `vuln_id` | Идентификатор уязвимости (GHSA / CVE / PYSEC) |
| `package_name` | Имя пакета |
| `published_at` | Дата публикации в OSV |
| `modified_at` | Дата обновления записи |
| `cwes` | Список CWE слабостей |
| `cvss_score` | Оценка критичности CVSS |
| `cvss_vector` | Вектор CVSS |
| `fixed_versions` | Исправленные версии (OSV) |
| `matched_fixed_version` | Выбранная исправленная стабильная версия |
| `fixed_release_datetime` | Дата релиза исправления в PyPI |
| `ttf_days` | Time-to-Fix: `(fixed_release - published) / 86400` |
| `fixed_before_published` | Исправлено до публичного раскрытия (CVD) |
