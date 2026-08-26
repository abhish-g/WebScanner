"""
Multi-provider LLM client.

Every free tier has its own quota. OpenRouter's free models are capped
at roughly 50 requests/day until you buy credits, which one enthusiastic
demo visitor can burn through in minutes. Chaining providers multiplies
the effective quota, since each has an independent limit.

All three providers below speak the OpenAI chat-completions format, so
only the base URL, key and model name change.
"""

import os

import requests

REQUEST_TIMEOUT = 60

# Ordered by preference. First one with a configured key wins; on
# failure we fall through to the next.
PROVIDERS = [
    {
        "name": "openrouter",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY",
        "model_env": "OPENROUTER_MODEL",
        # ":free" suffix matters. Without it you are paying per call.
        # Free model IDs change often, so verify current ones at
        # https://openrouter.ai/models?max_price=0
        "default_model": "deepseek/deepseek-chat-v3-0324:free",
    },
    {
        "name": "groq",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "key_env": "GROQ_API_KEY",
        "model_env": "GROQ_MODEL",
        "default_model": "llama-3.3-70b-versatile",
    },
    {
        "name": "gemini",
        "url": (
            "https://generativelanguage.googleapis.com"
            "/v1beta/openai/chat/completions"
        ),
        "key_env": "GEMINI_API_KEY",
        "model_env": "GEMINI_MODEL",
        "default_model": "gemini-2.5-flash",
    },
]


class LLMError(Exception):
    """Raised when every configured provider fails."""


def _call_provider(provider, system_prompt, user_prompt, max_tokens):
    api_key = os.getenv(provider["key_env"])
    if not api_key:
        return None, f"{provider['name']}: no API key configured"

    model = os.getenv(provider["model_env"], provider["default_model"])

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # OpenRouter uses these for its public app leaderboard. Harmless
    # elsewhere, so we always send them.
    if provider["name"] == "openrouter":
        headers["HTTP-Referer"] = os.getenv("APP_URL", "http://localhost")
        headers["X-Title"] = "WebScanner"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": max_tokens,
    }

    try:
        response = requests.post(
            provider["url"],
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"{provider['name']}: request failed ({exc.__class__.__name__})"

    if response.status_code != 200:
        detail = response.text[:200].replace("\n", " ")
        return None, (
            f"{provider['name']}: HTTP {response.status_code} - {detail}"
        )

    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        return None, f"{provider['name']}: unexpected response shape ({exc})"

    if not content or not content.strip():
        return None, f"{provider['name']}: empty response"

    return content.strip(), None


def complete(system_prompt: str, user_prompt: str, max_tokens: int = 450):
    """Try each provider in order. Returns (text, provider_name).

    Raises LLMError if all providers fail.
    """
    errors = []

    for provider in PROVIDERS:
        text, error = _call_provider(
            provider, system_prompt, user_prompt, max_tokens
        )

        if text is not None:
            return text, provider["name"]

        print(f"[LLM] {error}")
        errors.append(error)

    raise LLMError("All providers failed: " + " | ".join(errors))


def configured_providers():
    """Names of providers that have an API key set. Used by /health."""
    return [p["name"] for p in PROVIDERS if os.getenv(p["key_env"])]
