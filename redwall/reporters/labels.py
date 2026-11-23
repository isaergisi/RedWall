"""Section labels for human-readable reports (``en`` and ``tr``)."""

from __future__ import annotations

from typing import Dict

LABELS: Dict[str, Dict[str, str]] = {
    "en": {
        "why_open": "Why it is still open",
        "score": "Priority score",
        "how_to_close": "How to close it",
        "data_flow": "Data flow",
        "llm": "LLM second opinion (advisory, cannot hide the finding)",
        "llm_verdict": "exploitability",
        "llm_evidence": "cited lines",
        "llm_scenario": "attack scenario",
        "llm_fix": "suggested fix",
        "suppressed": "Suppressed inline (accepted with `redwall: ignore`, still listed)",
        "priority_order": "All findings in priority order",
        "nothing_hidden": "Nothing is hidden: every open finding is listed below in priority order, "
                          "followed by the inline-suppressed ones.",
        "filtered": "{n} finding(s) were left out because of filters you passed "
                    "(--min-severity / --min-confidence / --rules). Run without them to see everything.",
        "tiers": "P1 critical (score 80-100) · P2 high (60-79) · P3 medium (40-59) · P4 low (0-39)",
    },
    "tr": {
        "why_open": "Neden hâlâ açık",
        "score": "Öncelik puanı",
        "how_to_close": "Nasıl kapatılır",
        "data_flow": "Veri akışı",
        "llm": "LLM ikinci görüşü (tavsiye niteliğinde, bulguyu gizleyemez)",
        "llm_verdict": "istismar edilebilirlik",
        "llm_evidence": "gösterilen satırlar",
        "llm_scenario": "saldırı senaryosu",
        "llm_fix": "önerilen düzeltme",
        "suppressed": "Satır içinde susturulanlar (`redwall: ignore` ile kabul edildi, yine listeleniyor)",
        "priority_order": "Tüm bulgular, öncelik sırasıyla",
        "nothing_hidden": "Hiçbir bulgu gizlenmedi: açık bulguların hepsi aşağıda öncelik sırasıyla, ardından "
                          "satır içinde susturulanlar listeleniyor.",
        "filtered": "{n} bulgu verdiğiniz filtreler (--min-severity / --min-confidence / --rules) nedeniyle "
                    "rapora alınmadı. Hepsini görmek için filtresiz çalıştırın.",
        "tiers": "P1 kritik (puan 80-100) · P2 yüksek (60-79) · P3 orta (40-59) · P4 düşük (0-39)",
    },
}


def labels(lang: str) -> Dict[str, str]:
    return LABELS.get(lang, LABELS["en"])
