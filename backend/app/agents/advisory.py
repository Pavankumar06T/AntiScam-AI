"""Advisory Agent (RAG-powered).

Retrieves relevant guidance and generates a plain-language warning for the person
being targeted, citing the advisory it drew on.

Two things drive the design:

**This is the only agent the victim actually reads.** Everything else is
instrumentation. A warning that is accurate but unreadable — or that arrives in a
language the person doesn't think in — has failed. Hence EN/HI/TA output, a
headline that survives a two-second glance, and concrete actions rather than
"exercise caution".

**It must work without the LLM.** Retrieval is local (Chroma + ONNX MiniLM, no
tokens). If Groq is unavailable we fall back to a template built from the retrieved
advisory text. The warning gets blunter, not absent — the moment someone needs this
most is exactly when we cannot afford to be down.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.config import get_settings, resolve_model_name
from app.models.advisory_schemas import (
    AdvisoryCitation,
    AdvisoryWarning,
    Language,
    LANGUAGE_NAMES,
    WarningUrgency,
)
from app.models.schemas import ClassifyResponse, ScamType
from app.rag.knowledge_base import DISCLAIMER, Advisory
from app.rag.vector_store import retrieve

logger = logging.getLogger(__name__)


ADVISORY_SYSTEM_PROMPT = """\
You are the Advisory Agent of AntiScam AI. You speak DIRECTLY to a person who may \
be on a scam call right now. They may be frightened, and they may have been told \
for the last hour that they are a criminal.

Your warning has to work in the worst conditions: read in two seconds, on a phone, \
by someone in a panic, while a stranger shouts at them on another line.

Rules:
- Address them as "you". Never write about them in the third person.
- The headline must be under 12 words and state the conclusion, not a hedge.
  Good: "This is a scam. Hang up now." Bad: "Potential fraud indicators detected."
- The body is 2-4 short sentences. Say what is happening to them and why you are
  sure. Quote the specific thing the caller said that gives it away.
- immediate_actions: 3-5 concrete, physically performable steps in priority order.
  "Hang up the call" is an action. "Be vigilant" is not.
- Ground every factual claim in the ADVISORY CONTEXT provided. Do not invent legal
  provisions, section numbers, helpline numbers, or procedures. If the context does
  not support a claim, leave it out.
- Never shame them. People who fall for these are lawyers, doctors, professors.
  Say so if it helps them act.
- Do not promise their money is recoverable. Say what improves the odds.

Respond with a single JSON object ONLY, no markdown fences:

{
  "headline": "<under 12 words, decisive>",
  "body": "<2-4 short sentences, addressed to them>",
  "immediate_actions": ["<action 1>", "<action 2>", "..."]
}
"""


_URGENCY_BY_SCORE = [
    (85, WarningUrgency.CRITICAL),
    (70, WarningUrgency.WARNING),
    (45, WarningUrgency.CAUTION),
]


def _urgency_for(score: int) -> WarningUrgency:
    for threshold, urgency in _URGENCY_BY_SCORE:
        if score >= threshold:
            return urgency
    return WarningUrgency.INFO


def _build_query(detection: ClassifyResponse) -> str:
    """Turn a detection into a retrieval query.

    Uses the red flags rather than the raw transcript: the flags are already the
    distilled signal, and a long transcript would drown the query in filler.
    """
    parts = [detection.scam_type.value.replace("_", " ")]
    parts += [f.category.value.replace("_", " ") for f in detection.red_flags]
    parts += [f.quote for f in detection.red_flags[:4]]
    return " ".join(parts) or detection.reasoning


def _format_context(advisories: list[Advisory]) -> str:
    return "\n\n".join(
        f"[{a.id}] {a.title}\nSource: {a.source}\n{a.text}" for a in advisories
    )


# --- Template fallback ------------------------------------------------------
# Deliberately hand-written per language rather than machine-translated: a
# mistranslated safety instruction is worse than none.

_TEMPLATES: dict[Language, dict[str, Any]] = {
    Language.ENGLISH: {
        WarningUrgency.CRITICAL: {
            "headline": "This is a scam. Hang up now.",
            "body": (
                "The call you are on matches a known fraud pattern. No real officer "
                "arrests anyone over a video call, and no agency ever asks you to "
                "move money to prove it is clean. You are not in trouble — you are "
                "being targeted."
            ),
            "actions": [
                "Hang up the call immediately. You do not need their permission.",
                "Do not transfer any money, and do not share any OTP or PIN.",
                "Tell a family member or friend what just happened, right now.",
                "Call the National Cyber Crime Helpline on 1930.",
                "If you already paid, call 1930 immediately — the first hour matters most.",
            ],
        },
        WarningUrgency.WARNING: {
            "headline": "This call shows strong signs of fraud.",
            "body": (
                "Several things this caller said match a known scam script. Do not "
                "act on anything they tell you until you have verified it yourself, "
                "independently."
            ),
            "actions": [
                "Do not share any OTP, PIN, or password.",
                "Do not transfer money to any account they name.",
                "Hang up and call the organisation back on a number you look up yourself.",
                "Talk to someone you trust before you do anything.",
            ],
        },
        WarningUrgency.CAUTION: {
            "headline": "Be careful — parts of this call look suspicious.",
            "body": (
                "This call has some features that scams commonly use. It may be "
                "legitimate, but it is worth verifying before you act."
            ),
            "actions": [
                "Do not share credentials or transfer money yet.",
                "Hang up and call back on an official number you find yourself.",
                "A genuine caller will not mind you verifying.",
            ],
        },
    },
    Language.HINDI: {
        WarningUrgency.CRITICAL: {
            "headline": "यह धोखाधड़ी है। तुरंत कॉल काट दें।",
            "body": (
                "यह कॉल एक ज्ञात ठगी के तरीके से मेल खाती है। कोई भी असली अधिकारी "
                "वीडियो कॉल पर गिरफ्तार नहीं करता, और कोई भी एजेंसी आपसे पैसे "
                "ट्रांसफर करने को नहीं कहती। आप मुसीबत में नहीं हैं — आपको निशाना "
                "बनाया जा रहा है।"
            ),
            "actions": [
                "तुरंत कॉल काट दें। इसके लिए उनकी अनुमति की ज़रूरत नहीं है।",
                "कोई पैसा ट्रांसफर न करें, कोई OTP या PIN साझा न करें।",
                "अभी अपने परिवार या किसी दोस्त को यह बात बताएं।",
                "साइबर क्राइम हेल्पलाइन 1930 पर कॉल करें।",
                "अगर आपने पैसे भेज दिए हैं, तो तुरंत 1930 पर कॉल करें — पहला घंटा सबसे अहम है।",
            ],
        },
        WarningUrgency.WARNING: {
            "headline": "इस कॉल में ठगी के गंभीर संकेत हैं।",
            "body": (
                "इस कॉल करने वाले की कई बातें एक जानी-पहचानी ठगी की स्क्रिप्ट से "
                "मेल खाती हैं। जब तक आप खुद स्वतंत्र रूप से जाँच न कर लें, उनकी "
                "किसी भी बात पर अमल न करें।"
            ),
            "actions": [
                "कोई OTP, PIN या पासवर्ड साझा न करें।",
                "उनके बताए किसी भी खाते में पैसे ट्रांसफर न करें।",
                "कॉल काटें और खुद ढूंढे हुए नंबर पर संस्था को वापस कॉल करें।",
                "कुछ भी करने से पहले किसी भरोसेमंद व्यक्ति से बात करें।",
            ],
        },
        WarningUrgency.CAUTION: {
            "headline": "सावधान रहें — इस कॉल में कुछ बातें संदिग्ध हैं।",
            "body": (
                "इस कॉल में कुछ ऐसी बातें हैं जो अक्सर ठगी में इस्तेमाल होती हैं। "
                "यह असली भी हो सकती है, पर कुछ करने से पहले जाँच कर लेना बेहतर है।"
            ),
            "actions": [
                "अभी कोई जानकारी साझा न करें और न ही पैसे भेजें।",
                "कॉल काटकर खुद से ढूंढे गए आधिकारिक नंबर पर संपर्क करें।",
                "असली कॉल करने वाले को आपकी जाँच से कोई आपत्ति नहीं होगी।",
            ],
        },
    },
    Language.TAMIL: {
        WarningUrgency.CRITICAL: {
            "headline": "இது மோசடி. உடனே அழைப்பைத் துண்டியுங்கள்.",
            "body": (
                "இந்த அழைப்பு அறியப்பட்ட மோசடி முறையுடன் பொருந்துகிறது. உண்மையான "
                "அதிகாரி யாரும் வீடியோ அழைப்பில் கைது செய்வதில்லை; எந்த "
                "நிறுவனமும் பணத்தை மாற்றச் சொல்வதில்லை. நீங்கள் தவறு "
                "செய்யவில்லை — நீங்கள் குறிவைக்கப்படுகிறீர்கள்."
            ),
            "actions": [
                "உடனே அழைப்பைத் துண்டியுங்கள். அவர்களின் அனுமதி தேவையில்லை.",
                "பணம் அனுப்ப வேண்டாம்; OTP அல்லது PIN பகிர வேண்டாம்.",
                "இப்போதே உங்கள் குடும்பத்தினரிடம் அல்லது நண்பரிடம் சொல்லுங்கள்.",
                "சைபர் கிரைம் உதவி எண் 1930 ஐ அழையுங்கள்.",
                "ஏற்கனவே பணம் அனுப்பியிருந்தால், உடனே 1930 ஐ அழையுங்கள் — முதல் மணி நேரம் முக்கியம்.",
            ],
        },
        WarningUrgency.WARNING: {
            "headline": "இந்த அழைப்பில் மோசடியின் வலுவான அறிகுறிகள் உள்ளன.",
            "body": (
                "இந்த அழைப்பாளர் சொன்ன பல விஷயங்கள் அறியப்பட்ட மோசடி "
                "திட்டத்துடன் பொருந்துகின்றன. நீங்களே சரிபார்க்கும் வரை "
                "அவர்கள் சொல்வதைச் செய்ய வேண்டாம்."
            ),
            "actions": [
                "OTP, PIN அல்லது கடவுச்சொல்லைப் பகிர வேண்டாம்.",
                "அவர்கள் சொல்லும் எந்தக் கணக்கிற்கும் பணம் அனுப்ப வேண்டாம்.",
                "அழைப்பைத் துண்டித்து, நீங்களே தேடிய எண்ணில் திரும்ப அழையுங்கள்.",
                "எதையும் செய்வதற்கு முன் நம்பகமான ஒருவரிடம் பேசுங்கள்.",
            ],
        },
        WarningUrgency.CAUTION: {
            "headline": "கவனமாக இருங்கள் — இந்த அழைப்பு சந்தேகத்திற்குரியது.",
            "body": (
                "இந்த அழைப்பில் மோசடிகளில் பொதுவாகக் காணப்படும் சில அம்சங்கள் "
                "உள்ளன. இது உண்மையாகவும் இருக்கலாம், ஆனால் சரிபார்ப்பது நல்லது."
            ),
            "actions": [
                "இப்போதைக்கு தகவல் பகிரவோ பணம் அனுப்பவோ வேண்டாம்.",
                "அழைப்பைத் துண்டித்து அதிகாரப்பூர்வ எண்ணில் தொடர்பு கொள்ளுங்கள்.",
                "உண்மையான அழைப்பாளர் நீங்கள் சரிபார்ப்பதை எதிர்க்க மாட்டார்.",
            ],
        },
    },
}


def _template_warning(
    language: Language, urgency: WarningUrgency, advisories: list[Advisory], reason: str
) -> AdvisoryWarning:
    by_lang = _TEMPLATES.get(language, _TEMPLATES[Language.ENGLISH])
    # INFO has no template: nothing alarming happened, so say nothing alarming.
    template = by_lang.get(urgency) or by_lang[WarningUrgency.CAUTION]
    return AdvisoryWarning(
        language=language,
        urgency=urgency,
        headline=template["headline"],
        body=template["body"],
        immediate_actions=list(template["actions"]),
        citations=[
            AdvisoryCitation(advisory_id=a.id, title=a.title, source=a.source)
            for a in advisories
        ],
        disclaimer=DISCLAIMER,
        degraded=True,
    )


def _get_client():
    from groq import Groq

    settings = get_settings()
    return Groq(
        api_key=settings.groq_api_key,
        timeout=settings.request_timeout,
        max_retries=0,  # same rationale as the detector: never stall a live call
    )


def generate_warning(
    detection: ClassifyResponse,
    *,
    language: Language = Language.ENGLISH,
    graph_note: str | None = None,
) -> AdvisoryWarning:
    """Produce a warning for the person being targeted.

    graph_note: the fraud-graph finding, if any. Folded into the warning because
    "this account already hit two other people" is far more persuasive to someone
    mid-scam than any abstract risk score.
    """
    started = time.perf_counter()
    urgency = _urgency_for(detection.scam_probability)

    advisories = retrieve(
        _build_query(detection),
        scam_type=detection.scam_type.value,
        n_results=3,
    )

    if urgency is WarningUrgency.INFO:
        return AdvisoryWarning(
            language=language,
            urgency=urgency,
            headline="No fraud indicators detected.",
            body="This conversation does not match known scam patterns.",
            immediate_actions=[],
            citations=[],
            disclaimer=DISCLAIMER,
        )

    settings = get_settings()
    if not settings.groq_configured:
        return _template_warning(language, urgency, advisories, "no API key")

    context = _format_context(advisories)
    flags = "\n".join(
        f"- {f.category.value}: \"{f.quote}\"" for f in detection.red_flags[:8]
    )
    graph_section = f"\n\nFRAUD NETWORK FINDING:\n{graph_note}" if graph_note else ""

    user_prompt = f"""Write a warning in {LANGUAGE_NAMES[language]}.

DETECTION:
- Scam type: {detection.scam_type.value}
- Risk score: {detection.scam_probability}/100
- Assessment: {detection.reasoning}

RED FLAGS DETECTED:
{flags or "(none quoted)"}{graph_section}

ADVISORY CONTEXT (ground every factual claim in this):
{context}

Write the warning as JSON. The entire output — headline, body, and every action —
must be in {LANGUAGE_NAMES[language]}."""

    payload: dict[str, Any] | None = None
    last_error: Exception | None = None

    for attempt in (1, 2):
        try:
            client = _get_client()
            completion = client.chat.completions.create(
                model=resolve_model_name(),
                messages=[
                    {"role": "system", "content": ADVISORY_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3,
                max_completion_tokens=900,
                response_format={"type": "json_object"},
                seed=11,
            )
            payload = json.loads(completion.choices[0].message.content or "")
            if not isinstance(payload, dict) or not payload.get("headline"):
                raise ValueError("advisory payload missing headline")
            break
        except Exception as exc:
            last_error = exc
            payload = None
            logger.warning(
                "Advisory attempt %d/2 failed: %s: %s", attempt, type(exc).__name__, exc
            )
            if type(exc).__name__ == "RateLimitError":
                break

    if payload is None:
        logger.error("Advisory generation failed; using template. Last error: %s", last_error)
        return _template_warning(language, urgency, advisories, str(last_error))

    actions = payload.get("immediate_actions")
    if not isinstance(actions, list):
        actions = []

    elapsed = int((time.perf_counter() - started) * 1000)
    logger.info(
        "advisory generated lang=%s urgency=%s citations=%d latency_ms=%d",
        language.value, urgency.value, len(advisories), elapsed,
    )

    return AdvisoryWarning(
        language=language,
        urgency=urgency,
        headline=str(payload["headline"]).strip()[:160],
        body=str(payload.get("body", "")).strip()[:900],
        immediate_actions=[str(a).strip()[:200] for a in actions if str(a).strip()][:6],
        citations=[
            AdvisoryCitation(advisory_id=a.id, title=a.title, source=a.source)
            for a in advisories
        ],
        disclaimer=DISCLAIMER,
        degraded=False,
    )
