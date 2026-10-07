# Анализ жизненного цикла уязвимостей в PyPI (Time-to-Fix)

Исследование времени устранения уязвимостей (**Time-to-Fix**, TTF) в экосистеме Python на основе открытых данных **OSV** и реестра **PyPI**.

## Источники данных
- [OSV PyPI Dump](https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip)
- [PyPI JSON API](https://pypi.org/pypi/{package}/json)

## Структура репозитория

```text
python-fix-time/
├── data/
│   ├── raw/                  # Дампы OSV и кэш PyPI
│   └── processed/            # ttf_dataset.parquet и ttf_dataset.csv
├── notebooks/
│   └── data_exploration.ipynb
├── ttf_pipeline/             # Логика клиентов, парсеров и расчет метрик
├── fetch_osv.py              # Скачивание и парсинг дампа OSV
├── fetch_pypi.py             # Сбор дат релизов из PyPI API
├── build_dataset.py          # Расчет TTF и сборка датасета
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
