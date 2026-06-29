"""
utils/llm.py

Central LLM utility for ShieldLabs.
Provides a single ask_llm() function that abstracts away
which model is being used. Supports Groq (cloud) and
Ollama (local) with automatic fallback.
"""

import logging                  # For printing structured logs
import httpx                    # For making HTTP requests to Ollama
from groq import Groq           # Official Groq SDK
from groq import APIError, APIConnectionError, RateLimitError  # Groq errors

from core.config import settings  # Our settings from .env

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────

# Creates a logger specifically for this file.
# When you see logs, they'll show "shieldlabs.llm" as the source.
logger = logging.getLogger("shieldlabs.llm")


# ─────────────────────────────────────────────
# GROQ CLIENT
# ─────────────────────────────────────────────

# We create the Groq client ONCE here at module level.
# Why? Creating it is slightly expensive. By doing it once
# and reusing it, we save time on every request.
groq_client = Groq(api_key=settings.groq_api_key)


# ─────────────────────────────────────────────
# INTERNAL FUNCTIONS
# ─────────────────────────────────────────────

def _ask_groq(prompt: str, max_tokens: int = 1024) -> str:
    """
    Send a prompt to Groq API and return the response text.

    The underscore prefix (_) means this is a private function.
    It's only meant to be called from within this file, not from outside.

    Args:
        prompt: The question or instruction to send to the AI
        max_tokens: Maximum length of the response (1 token ≈ 4 characters)

    Returns:
        The AI's response as a plain string

    Raises:
        Exception: If Groq API call fails
    """
    logger.info(f"Asking Groq ({settings.groq_model})...")

    # This is the actual API call to Groq
    response = groq_client.chat.completions.create(
        model=settings.groq_model,

        # messages is a list of turns in the conversation.
        # "role: user" means this is the human speaking.
        # "role: assistant" would be the AI's previous replies.
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity expert assistant for ShieldLabs. "
                    "Analyze code and security issues accurately and concisely."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        max_tokens=max_tokens,

        # temperature controls randomness.
        # 0.0 = very focused and deterministic (good for analysis)
        # 1.0 = very creative and random (good for writing)
        # We use 0.3 — mostly focused but not robotic
        temperature=0.3,
    )

    # Extract just the text from the response object
    result = response.choices[0].message.content
    logger.info("Groq responded successfully.")
    return result


def _ask_ollama(prompt: str, max_tokens: int = 1024) -> str:
    """
    Send a prompt to local Ollama and return the response text.

    We call Ollama's REST API directly using httpx (HTTP client).
    Ollama runs on localhost:11434 on your machine.

    Args:
        prompt: The question or instruction to send to the AI
        max_tokens: Maximum length of the response

    Returns:
        The AI's response as a plain string

    Raises:
        Exception: If Ollama is not running or request fails
    """
    logger.info(f"Asking Ollama ({settings.ollama_model})...")

    # httpx.Client is like requests but more modern.
    # timeout=120.0 means: wait up to 120 seconds for a response.
    # Local models are slower than cloud APIs, so we give it time.
    with httpx.Client(timeout=120.0) as client:
        response = client.post(
            f"{settings.ollama_base_url}/api/generate",
            json={
                "model": settings.ollama_model,
                "prompt": prompt,
                "stream": False,        #  Get full response at once, not word by word
                "options": {
                    "num_predict": max_tokens,  #  Ollama's name for max_tokens
                    "temperature": 0.3,
                }
            }
        )

        # raise_for_status() checks if the HTTP response was successful.
        # If Ollama returned an error (4xx or 5xx), this raises an exception.
        response.raise_for_status()

        # Parse the JSON response and extract the text
        result = response.json()["response"]
        logger.info("Ollama responded successfully.")
        return result


# ─────────────────────────────────────────────
# PUBLIC FUNCTION — This is what the rest of the app uses
# ─────────────────────────────────────────────

def ask_llm(
    prompt: str,
    max_tokens: int = 1024,
    prefer_local: bool = False
) -> dict:
    """
    Main LLM interface for ShieldLabs.

    Tries Groq first (unless prefer_local=True), then falls back
    to Ollama if Groq fails. Always returns a consistent dict.

    Args:
        prompt: Your question or instruction
        max_tokens: How long the response can be
        prefer_local: If True, use Ollama first (for privacy)

    Returns:
        {
            "success": True/False,
            "response": "the AI's answer" or None,
            "model_used": "which model answered",
            "error": "error message" or None
        }

    Example:
        result = ask_llm("Is this SQL query vulnerable?")
        if result["success"]:
            print(result["response"])
    """

    # If prefer_local is True, try Ollama first
    if prefer_local:
        try:
            response = _ask_ollama(prompt, max_tokens)
            return {
                "success": True,
                "response": response,
                "model_used": f"ollama/{settings.ollama_model}",
                "error": None
            }
        except Exception as e:
            # Ollama failed, log the warning and fall through to Groq
            logger.warning(f"Ollama failed: {e}. Trying Groq...")

    # Try Groq (default path)
    try:
        response = _ask_groq(prompt, max_tokens)
        return {
            "success": True,
            "response": response,
            "model_used": f"groq/{settings.groq_model}",
            "error": None
        }

    except RateLimitError:
        # Hit Groq's free tier limit (150 req/day)
        logger.warning("Groq rate limit hit. Falling back to Ollama...")

    except APIConnectionError:
        # No internet or Groq is down
        logger.warning("Groq connection failed. Falling back to Ollama...")

    except APIError as e:
        # Some other Groq error
        logger.warning(f"Groq API error: {e}. Falling back to Ollama...")

    # Groq failed — try Ollama as fallback
    try:
        response = _ask_ollama(prompt, max_tokens)
        return {
            "success": True,
            "response": response,
            "model_used": f"ollama/{settings.ollama_model}",
            "error": None
        }

    except Exception as e:
        # Both failed — return a clean error dict
        logger.error(f"Both Groq and Ollama failed. Last error: {e}")
        return {
            "success": False,
            "response": None,
            "model_used": None,
            "error": str(e)
        }


def analyze_code_security(code: str, language: str = "python") -> dict:
    """
    Specialized function for code security analysis.
    Wraps ask_llm with a security-focused prompt.

    Args:
        code: The source code to analyze
        language: Programming language of the code

    Returns:
        Same dict as ask_llm()
    """

    # This is a carefully crafted prompt for security analysis.
    # The more specific your prompt, the better the AI response.
    prompt = f"""Analyze this {language} code for security vulnerabilities.

For each vulnerability found, provide:
1. Vulnerability type (e.g., SQL Injection, XSS, Hardcoded Secret)
2. Severity: CRITICAL / HIGH / MEDIUM / LOW
3. Line description (what the vulnerable code does)
4. Why it is dangerous
5. How to fix it

Code to analyze:
```{language}
{code}
```

Be specific and concise. If no vulnerabilities found, say "No vulnerabilities detected."
"""

    # Use local Ollama for code analysis — keeps sensitive code private
    return ask_llm(prompt, max_tokens=2048, prefer_local=True)


def explain_vulnerability(vuln_type: str, context: str = "") -> dict:
    """
    Explains a vulnerability in plain English.
    Uses Groq (smarter model) for better explanations.

    Args:
        vuln_type: e.g., "SQL Injection", "XSS"
        context: Optional extra context about where it was found

    Returns:
        Same dict as ask_llm()
    """

    prompt = f"""Explain this security vulnerability in simple terms for a developer:

Vulnerability: {vuln_type}
{f"Context: {context}" if context else ""}

Provide:
1. What it is (1-2 sentences, simple language)
2. Real-world impact (what an attacker could do)
3. Quick fix recommendation

Keep it concise and practical.
"""
    # Use Groq for explanations — better at clear communication
    return ask_llm(prompt, max_tokens=512, prefer_local=False)