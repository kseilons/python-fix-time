import glob
import pandas as pd
from scipy import stats


def main():
    json_files = glob.glob("data/processed/ttf_spark_final.json/part-*.json")
    if not json_files:
        raise FileNotFoundError("Не найден файл результата Spark в data/processed/ttf_spark_final.json/")

    df = pd.read_json(json_files, lines=True)
    print(f"Загружено записей из витрины Spark: {len(df)}")

    print("\n" + "=" * 75)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ СТАТИСТИЧЕСКИХ ГИПОТЕЗ (уровень значимости alpha = 0.05)")
    print("=" * 75)

    post_df = df[df["ttf_days"].notna() & (df["ttf_days"] >= 0)].copy()

    high_crit = post_df[post_df["cvss_score"] >= 7.0]["ttf_days"]
    low_med = post_df[post_df["cvss_score"] < 7.0]["ttf_days"]
    u1, p1 = stats.mannwhitneyu(high_crit, low_med, alternative="two-sided")
    print(f"\n[Гипотеза H1]: Критические/высокие (CVSS >= 7) vs Средние/низкие (CVSS < 7)")
    print(f"  Выборки: n1={len(high_crit)} (медиана {high_crit.median():.2f} дн.) vs n2={len(low_med)} (медиана {low_med.median():.2f} дн.)")
    print(f"  Критерий Манна-Уитни: U = {u1:.1f}, p-value = {p1:.4e} -> {'ОТВЕРГАЕМ H0 (различия значимы)' if p1 < 0.05 else 'НЕТ оснований отвергнуть H0 (различия незначимы)'}")

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

    corr_s, p3 = stats.spearmanr(post_df["package_releases_count"], post_df["ttf_days"])
    print(f"\n[Гипотеза H3]: Влияние активности пакета (числа релизов PyPI) на TTF")
    print(f"  Ранговая корреляция Спирмена: r = {corr_s:.4f}, p-value = {p3:.4e} -> {'ОТВЕРГАЕМ H0 (связь статистически значима)' if p3 < 0.05 else 'НЕТ оснований отвергнуть H0'}")
    print("=" * 75)


if __name__ == "__main__":
    main()
