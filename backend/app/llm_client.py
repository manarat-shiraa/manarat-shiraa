"""طبقة الذكاء الاصطناعي الموحّدة.

القرار (الخطورة والأولوية) يطلع من القواعد والظل الرقمي، والنموذج دوره يشرح ويكتب التقرير.
لو النموذج مو متاح أو تأخر، نرجع للنص الجاهز (fallback) فالنظام ما يوقف أبداً.

LLM_PROVIDER في ملف .env:
- none   : بدون نموذج، شرح جاهز من القوالب (الافتراضي، مناسب للتطوير والديمو بدون نت)
- ollama : نموذج محلي عبر Ollama (البيانات ما تطلع من الجهاز)
- openai : أي خدمة متوافقة مع OpenAI Chat Completions (بيانات وهمية فقط)
"""
from __future__ import annotations

import logging

import httpx

from . import config

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "أنت مساعد لمحلل مركز عمليات أمنية (SOC). اكتب بالعربية الفصحى المبسطة، بجمل قصيرة ودقيقة. "
    "اعتمد فقط على الحقائق المعطاة لك، ولا تخترع عناوين أو أرقام أو أحداث غير موجودة. "
    "لا تغيّر مستوى الخطورة المعطى لك، مهمتك الشرح فقط."
)


def generate(prompt: str, fallback: str, max_tokens: int = 400) -> tuple[str, str]:
    """يرجّع (النص، مصدره). المصدر: اسم المزوّد أو template."""
    provider = config.LLM_PROVIDER
    if provider == "none":
        return fallback, "template"
    try:
        if provider == "ollama":
            r = httpx.post(
                f"{config.OLLAMA_URL}/api/chat",
                json={
                    "model": config.LLM_MODEL,
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": max_tokens},
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                },
                timeout=config.LLM_TIMEOUT,
            )
            r.raise_for_status()
            text = r.json()["message"]["content"].strip()
            return (text or fallback), "ollama"
        if provider == "openai":
            r = httpx.post(
                f"{config.OPENAI_BASE_URL.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"},
                json={
                    "model": config.LLM_MODEL,
                    "temperature": 0.2,
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                },
                timeout=config.LLM_TIMEOUT,
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"].strip()
            return (text or fallback), "openai"
    except Exception as exc:  # أي خطأ = نرجع للقالب ونكمل
        log.warning("LLM call failed (%s), using template: %s", provider, exc)
    return fallback, "template"
