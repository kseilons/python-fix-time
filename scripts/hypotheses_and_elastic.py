import glob
import json
import pandas as pd
from scipy import stats
from elasticsearch import Elasticsearch, helpers

ES_HOST = "http://localhost:9200"
INDEX_NAME = "pypi-vulnerabilities"


def main():
    json_files = glob.glob("data/processed/ttf_spark_final.json/part-*.json")
    if not json_files:
        raise FileNotFoundError("Не найден файл результата Spark в data/processed/ttf_spark_final.json/")

    df = pd.read_json(json_files, lines=True)
    print(f"Загружено записей из витрины Spark: {len(df)}")

    # ЗАДАЧА 5: Проверка статистических гипотез 
    print("\n" + "=" * 75)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ СТАТИСТИЧЕСКИХ ГИПОТЕЗ (уровень значимости alpha = 0.05)")
    print("=" * 75)

    post_df = df[df["ttf_days"].notna() & (df["ttf_days"] >= 0)].copy()

    # Гипотеза H1: Уровень критичности (High/Critical vs Low/Medium) влияет на скорость патча
    high_crit = post_df[post_df["cvss_score"] >= 7.0]["ttf_days"]
    low_med = post_df[post_df["cvss_score"] < 7.0]["ttf_days"]
    u1, p1 = stats.mannwhitneyu(high_crit, low_med, alternative="two-sided")
    print(f"\n[Гипотеза H1]: Критические/высокие (CVSS >= 7) vs Средние/низкие (CVSS < 7)")
    print(f"  Выборки: n1={len(high_crit)} (медиана {high_crit.median():.2f} дн.) vs n2={len(low_med)} (медиана {low_med.median():.2f} дн.)")
    print(f"  Критерий Манна-Уитни: U = {u1:.1f}, p-value = {p1:.4e} -> {'ОТВЕРГАЕМ H0 (различия значимы)' if p1 < 0.05 else 'НЕТ оснований отвергнуть H0 (различия незначимы)'}")

    # Гипотеза H2: Тип уязвимости (категория CWE) влияет на скорость устранения
    top_cwes = [
        "Memory Corruption / Переполнение буфера",
        "Path Traversal (Обход пути)",
        "XSS (Межсайтовый скриптинг)",
        "DoS / Отказ в обслуживании",
        "Deserialization (Небезопасная десериализация)",
    ]
    groups = [post_df[post_df["cwe_category"] == c]["ttf_days"] for c in top_cwes]
    kw_stat, p2 = stats.kruskal(*groups)
    print(f"\n[Гипотеза H2]: Влияние категории CWE (сравнение 5 основных типов дефектов)")
    print(f"  Критерий Краскела-Уоллиса: H = {kw_stat:.2f}, p-value = {p2:.4e} -> {'ОТВЕРГАЕМ H0 (тип CWE значимо влияет)' if p2 < 0.05 else 'НЕТ оснований отвергнуть H0 (тип CWE не дает значимых различий)'}")

    # Гипотеза H3: Популярность/активность пакета (число релизов) влияет на скорость патча
    corr_s, p3 = stats.spearmanr(post_df["package_releases_count"], post_df["ttf_days"])
    print(f"\n[Гипотеза H3]: Влияние активности пакета (числа релизов PyPI) на TTF")
    print(f"  Ранговая корреляция Спирмена: r = {corr_s:.4f}, p-value = {p3:.4e} -> {'ОТВЕРГАЕМ H0 (связь статистически значима)' if p3 < 0.05 else 'НЕТ оснований отвергнуть H0'}")
    print("=" * 75)

    # ЗАГРУЗКА В ELASTICSEARCH ДЛЯ ДАШБОРДА KIBANA 
    print("\n--- Загрузка данных в Elasticsearch для визуализации в Kibana ---")
    es = Elasticsearch(ES_HOST)
    if es.indices.exists(index=INDEX_NAME):
        es.indices.delete(index=INDEX_NAME)

    records = json.loads(df.to_json(orient="records", date_format="iso"))
    actions = [{"_index": INDEX_NAME, "_id": f"{r['vuln_id']}_{r['package_name']}", "_source": r} for r in records]

    success, _ = helpers.bulk(es, actions, chunk_size=2000)
    es.indices.refresh(index=INDEX_NAME)
    print(f"Успешно загружено в Elasticsearch (индекс '{INDEX_NAME}'): {success} документов!")


if __name__ == "__main__":
    main()
