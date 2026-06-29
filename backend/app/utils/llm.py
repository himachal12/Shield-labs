"""LLM utility with Groq and Ollama fallback."""

import logging

import httpx

from app.config import settings

try:
    from groq import APIConnectionError, APIError, Groq, RateLimitError
except ImportError:
    APIConnectionError = APIError = RateLimitError = Exception
    Groq = None

logger = logging.getLogger("shieldlabs.llm")


def _ask_groq(prompt: str, max_tokens: int = 1024) -> str:
    if Groq is None:
        raise RuntimeError("Groq SDK is not installed")
    if not settings.groq_api_key:
        raise RuntimeError("GROQ_API_KEY is not configured")
    client = Groq(api_key=settings.groq_api_key)
    response = client.chat.completions.create(
        model=settings.groq_model,
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert assistant for ShieldLabs."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.3,
    )
    return response.choices[0].message.content


def _ask_ollama(prompt: str, max_tokens: int = 1024) -> str:
    with httpx.Client(timeout=120.0) as client:
        response = client.post(
            f"{settings.ollama_base_url}/api/generate",
            json={"model": settings.ollama_model, "prompt": prompt, "stream": False, "options": {"num_predict": max_tokens, "temperature": 0.3}},
        )
        response.raise_for_status()
        return response.json()["response"]


def ask_llm(prompt: str, max_tokens: int = 1024, prefer_local: bool = False) -> dict:
    providers = [_ask_ollama, _ask_groq] if prefer_local else [_ask_groq, _ask_ollama]
    last_error = None
    for provider in providers:
        try:
            response = provider(prompt, max_tokens)
            model = settings.ollama_model if provider is _ask_ollama else settings.groq_model
            prefix = "ollama" if provider is _ask_ollama else "groq"
            return {"success": True, "response": response, "model_used": f"{prefix}/{model}", "error": None}
        except Exception as exc:
            last_error = exc
            logger.warning("LLM provider failed: %s", exc)
    return {"success": False, "response": None, "model_used": None, "error": str(last_error)}


def analyze_code_security(code: str, language: str = "python") -> dict:
    prompt = (
        f"Analyze this {language} code for security vulnerabilities. "
        "For each issue, provide type, severity, location, impact, and fix.\n\n"
        f"Code:\n{code}"
    )
    return ask_llm(prompt, max_tokens=2048, prefer_local=True)


def explain_vulnerability(vuln_type: str, context: str = "") -> dict:
    prompt = f"Explain this security vulnerability for a developer: {vuln_type}\n{context}"
    return ask_llm(prompt, max_tokens=512, prefer_local=False)
