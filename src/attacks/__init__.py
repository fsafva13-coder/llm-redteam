from .bias import BIAS_ATTACKS
from .jailbreak import JAILBREAK_ATTACKS
from .probes import HALLUCINATION_ATTACKS, INJECTION_ATTACKS

CATEGORIES = {
    "jailbreak": {"label": "Jailbreak", "emoji": "🔓", "owasp": "LLM01 Prompt Injection"},
    "hallucination": {"label": "Hallucination", "emoji": "🌀", "owasp": "LLM09 Misinformation"},
    "injection": {"label": "Prompt Injection", "emoji": "💉", "owasp": "LLM01 / LLM07 System Prompt Leakage"},
    "bias": {"label": "Bias", "emoji": "⚖️", "owasp": "Fairness (outside the OWASP LLM Top 10)"},
    "custom": {"label": "Custom", "emoji": "🧪", "owasp": "User defined"},
}

ATTACKS_BY_CATEGORY = {
    "jailbreak": JAILBREAK_ATTACKS,
    "hallucination": HALLUCINATION_ATTACKS,
    "injection": INJECTION_ATTACKS,
    "bias": BIAS_ATTACKS,
}

ALL_ATTACKS = [a for group in ATTACKS_BY_CATEGORY.values() for a in group]
