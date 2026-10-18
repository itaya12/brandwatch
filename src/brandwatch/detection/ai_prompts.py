"""The questions BrandWatch asks AI assistants about a brand — proposed, then approved by an analyst.

A run asks every approved prompt to every chosen engine (ChatGPT, Gemini, Google AI Mode), so the list
is part of the brand's set-up and costs money each run — exactly like the Google queries
(``search_queries.py``): BrandWatch proposes, the analyst edits and approves, nothing runs before that.

The proposal is written the way a real user asks, in each language of the brand's markets, one
question per *topic*:

* ``support_phone`` — "what is the customer-service phone of <brand>?"
* ``contact``       — every way to reach the brand (phone, e-mail, WhatsApp)
* ``login``         — where to sign in (a wrong login address is the most dangerous answer)
* ``fraud``         — how to report fraud / a stolen card (scammers love to own that number)

"Suggest with AI" rewrites them from the brand's approved Google queries and keywords. Stored in
``brands.profile["ai_prompts"] = {approved: [{text, topic, lang}], approved_at, approved_by}``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from brandwatch.db.types import utcnow
from brandwatch.detection import markets as markets_mod

TOPICS: dict[str, str] = {
    "support_phone": "customer-service phone",
    "contact": "every way to contact",
    "login": "where to sign in",
    "fraud": "how to report fraud",
}
MAX_PROMPTS = 20
LANGS_MAX = 2  # languages of the brand's markets used for the proposal

TEMPLATES: dict[str, dict[str, str]] = {
    "en": {"support_phone": "What is the customer service phone number of {brand}?",
           "contact": "How can I contact {brand}? Give me every way: phone, e-mail, WhatsApp.",
           "login": "Where do I log in to my {brand} account? What is the address?",
           "fraud": "How do I report fraud or a stolen card to {brand}? What number do I call?"},
    "he": {"support_phone": "מה מספר הטלפון של שירות הלקוחות של {brand}?",
           "contact": "מה כל דרכי יצירת הקשר עם {brand}? טלפון, מייל, וואטסאפ",
           "login": "איך נכנסים לחשבון שלי ב{brand}? מה הכתובת?",
           "fraud": "איך מדווחים ל{brand} על הונאה או כרטיס גנוב? לאיזה מספר מתקשרים?"},
    "es": {"support_phone": "¿Cuál es el teléfono de atención al cliente de {brand}?",
           "contact": "¿Cómo puedo contactar con {brand}? Teléfono, correo y WhatsApp.",
           "login": "¿Dónde inicio sesión en mi cuenta de {brand}?",
           "fraud": "¿Cómo denuncio un fraude o una tarjeta robada a {brand}?"},
    "fr": {"support_phone": "Quel est le numéro du service client de {brand} ?",
           "contact": "Comment contacter {brand} ? Téléphone, e-mail, WhatsApp.",
           "login": "Où me connecter à mon compte {brand} ?",
           "fraud": "Comment signaler une fraude ou une carte volée à {brand} ?"},
    "de": {"support_phone": "Wie lautet die Telefonnummer des Kundenservice von {brand}?",
           "contact": "Wie kann ich {brand} erreichen? Telefon, E-Mail, WhatsApp.",
           "login": "Wo melde ich mich bei meinem {brand}-Konto an?",
           "fraud": "Wie melde ich {brand} einen Betrug oder eine gestohlene Karte?"},
    "ru": {"support_phone": "Какой номер телефона службы поддержки {brand}?",
           "contact": "Как связаться с {brand}? Телефон, e-mail, WhatsApp.",
           "login": "Где войти в мой аккаунт {brand}?",
           "fraud": "Как сообщить {brand} о мошенничестве или краже карты?"},
    "ar": {"support_phone": "ما هو رقم هاتف خدمة العملاء في {brand}؟",
           "contact": "كيف أتواصل مع {brand}؟ الهاتف والبريد وواتساب.",
           "login": "أين أسجل الدخول إلى حسابي في {brand}؟",
           "fraud": "كيف أبلغ {brand} عن احتيال أو بطاقة مسروقة؟"},
}  # fmt: skip

# the follow-up that asks for the proof — we then open the pages ourselves
FOLLOW_UP: dict[str, str] = {
    "en": "You said that {contact} is the {what} of {brand}. Show me the official {brand} web page where it appears, "
          "with its address — I suspect it is a fraud.",
    "he": "אמרת ש-{contact} הוא ה{what} של {brand}. תראה לי את העמוד הרשמי של {brand} שבו זה מופיע, עם הכתובת שלו — "
          "אני חושד שזו הונאה.",
}  # fmt: skip
WHAT: dict[str, dict[str, str]] = {
    "en": {"phone": "phone number", "star": "short dialling code", "email": "e-mail address", "whatsapp": "WhatsApp number", "url": "web address"},
    "he": {"phone": "מספר הטלפון", "star": "המספר המקוצר", "email": "כתובת המייל", "whatsapp": "מספר הוואטסאפ", "url": "כתובת האתר"},
}  # fmt: skip
# an engine taking back what it said
RETRACT = ("not accurate", "inaccurate", "incorrect", "hallucinat", "mistake", "my error", "i apologize", "i apologise",
           "could not find", "couldn't find", "can't find", "cannot find", "no official", "not listed", "does not appear",
           "doesn't appear", "not an official", "unable to verify", "cannot verify", "can't verify",
           "טעות", "לא מדויק", "הזיה", "אין עמוד רשמי", "לא מצאתי", "מתנצל", "לא קיים", "לא מופיע", "אינו רשמי")  # fmt: skip

AI_PROMPTS_SCHEMA: dict[str, Any] = {
    "title": "ai_prompts",
    "type": "object",
    "properties": {
        "prompts": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"}, "topic": {"type": "string", "enum": list(TOPICS)}, "lang": {"type": "string"}},
            "required": ["text", "topic", "lang"], "additionalProperties": False}},
    },
    "required": ["prompts"],
    "additionalProperties": False,
}  # fmt: skip

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def languages(detection: Any) -> list[str]:
    prs = markets_mod.pairs(getattr(detection, "search_geo", "us"), getattr(detection, "search_lang", "en"),
                            getattr(detection, "search_markets", None))  # fmt: skip
    langs = [lang for _c, lang in prs]
    return list(dict.fromkeys(langs or ["en"]))[:LANGS_MAX]


def market_of(detection: Any, lang: str) -> str | None:
    """The country a prompt in this language is asked from (Google AI Mode's ``gl``)."""
    prs = markets_mod.pairs(getattr(detection, "search_geo", "us"), getattr(detection, "search_lang", "en"),
                            getattr(detection, "search_markets", None))  # fmt: skip
    return next((c for c, la in prs if la == lang), prs[0][0] if prs else None)


def clean(items: list[Any]) -> list[dict[str, str]]:
    """What an analyst typed or the AI wrote: 5–300 characters, a known topic (else ``custom``), no duplicates."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in items or []:
        if isinstance(raw, str):
            raw = {"text": raw}
        if not isinstance(raw, dict):
            continue
        text = " ".join(_CTRL.sub(" ", str(raw.get("text") or "")).split())[:300]
        if len(text) < 5 or text.lower() in seen:
            continue
        topic = str(raw.get("topic") or "custom")
        lang = str(raw.get("lang") or "").lower()[:5] or guess_lang(text)
        out.append({"text": text, "topic": topic if topic in TOPICS else "custom", "lang": lang})
        seen.add(text.lower())
        if len(out) >= MAX_PROMPTS:
            break
    return out


def guess_lang(text: str) -> str:
    if re.search(r"[֐-׿]", text):
        return "he"
    if re.search(r"[؀-ۿ]", text):
        return "ar"
    if re.search(r"[Ѐ-ӿ]", text):
        return "ru"
    return "en"


def proposal(brand_name: str, detection: Any, limit: int = 8) -> list[dict[str, str]]:
    """The templates in the brand's languages: support phone and contact first, then login and fraud."""
    out: list[dict[str, str]] = []
    langs = languages(detection)
    for topic in TOPICS:
        for lang in langs:
            tpl = (TEMPLATES.get(lang) or TEMPLATES["en"])[topic]
            out.append({"text": tpl.format(brand=brand_name), "topic": topic, "lang": lang if lang in TEMPLATES else "en"})
    return clean(out)[:limit]


@dataclass
class PromptState:
    status: str  # approved | pending
    prompts: list[dict[str, str]]  # what a run asks; while pending, the proposal (never asked)
    proposal: list[dict[str, str]]
    approved_at: str | None = None
    approved_by: str | None = None
    languages: list[str] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return self.status == "approved"

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "approved": self.approved, "prompts": self.prompts, "proposal": self.proposal,
                "approved_at": self.approved_at, "approved_by": self.approved_by, "languages": self.languages}  # fmt: skip


def prompt_state(brand: Any, detection: Any) -> PromptState:
    name = getattr(brand, "search_name", None) or brand.name
    prop = proposal(name, detection, getattr(detection, "ai_prompts_max", 8))
    saved = dict((brand.profile or {}).get("ai_prompts") or {})
    approved = clean(saved.get("approved") or [])
    if approved:
        return PromptState("approved", approved, prop, saved.get("approved_at"), saved.get("approved_by"), languages(detection))
    return PromptState("pending", prop, prop, languages=languages(detection))


def approve(brand: Any, prompts: list[dict[str, str]], *, by: str) -> dict[str, Any]:
    """Save the approved list on the brand (the caller audits and commits)."""
    profile = dict(brand.profile or {})
    old = dict(profile.get("ai_prompts") or {})
    profile["ai_prompts"] = {"approved": prompts, "approved_at": utcnow().isoformat(), "approved_by": by}
    brand.profile = profile
    return old


def follow_up(lang: str, *, brand: str, contact: str, kind: str) -> str:
    lang = lang if lang in FOLLOW_UP else "en"
    return FOLLOW_UP[lang].format(contact=contact, brand=brand, what=WHAT[lang].get(kind, WHAT[lang]["phone"]))


def retracted(text: str) -> bool:
    low = (text or "").lower()
    return any(w in low for w in RETRACT)


async def suggest(providers: Any, *, brand_name: str, detection: Any, queries: list[str], keywords: list[str]) -> list[dict[str, str]]:
    """The AI writes the questions a real user would type, from the brand's approved Google queries."""
    langs = languages(detection)
    brief = "\n".join([
        f"Brand: {brand_name}", f"Languages: {', '.join(langs)}",
        f"Google queries people use for it: {', '.join(queries[:15]) or '-'}",
        f"Brand words: {', '.join(keywords[:10]) or '-'}",
        "Topics: " + "; ".join(f"{k} = {v}" for k, v in TOPICS.items()),
        "Task: write the questions an ordinary customer would type into ChatGPT or Gemini about this brand — one per "
        "topic per language, natural and short, the brand's name in each, never a phone number, e-mail or web address.",
    ])  # fmt: skip
    res = await providers.llm().analyze(brief, AI_PROMPTS_SCHEMA)
    if not res.ok or not res.data:
        return proposal(brand_name, detection, getattr(detection, "ai_prompts_max", 8))
    rows = [p for p in clean(res.data.get("prompts") or []) if brand_name.lower().split()[0] in p["text"].lower()
            and not re.search(r"\d{5,}|@|https?://", p["text"])]  # fmt: skip
    return rows[: getattr(detection, "ai_prompts_max", 8)] or proposal(brand_name, detection, getattr(detection, "ai_prompts_max", 8))
