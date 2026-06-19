# scanner/llm_explainer.py
# scanner/llm_explainer.py

import os
from groq import Groq
from dotenv import load_dotenv
import streamlit as st

load_dotenv()
# Safe for both CLI and Streamlit
def _get_api_key() -> str:
    try:
        if hasattr(st, "secrets") and "GROQ_API_KEY" in st.secrets:
            return st.secrets["GROQ_API_KEY"]
    except Exception:
        pass
    return os.getenv("GROQ_API_KEY")

api_key = _get_api_key()


client = Groq(api_key=api_key)

MODEL = 'llama-3.3-70b-versatile'

PROMPT_TEMPLATE = """You are a senior security engineer reviewing code for vulnerabilities.

The following {language} code has been flagged by static analysis.
Rule triggered: {rule}
Static analysis message: {message}

Code:
```{language}
{code}
```

Respond in exactly this format — no extra text outside it:

EXPLANATION:
<2-3 sentences explaining specifically why this code is dangerous and what an attacker could do>

FIX:
<the corrected code only, no commentary>
"""


def explain_vulnerability(
    code: str,
    rule: str,
    message: str,
    severity: str,
    language: str
) -> dict:
    """
    Send a flagged code chunk to Groq LLM and get back a structured explanation.

    Returns:
        {
            'explanation': str,
            'fix': str,
            'severity': str,
            'severity_reason': str,
            'raw': str          # full LLM response, kept for debugging
        }
    """
    prompt = PROMPT_TEMPLATE.format(
        code=code,
        rule=rule,
        message=message,
        language=language
    )

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=800,
            temperature=0.2   # low temperature = more consistent, less hallucination
        )
        raw = response.choices[0].message.content
        return _parse_llm_response(raw)

    except Exception as e:
        print(f"[ERROR] Groq API call failed: {e}")
        return {
            'explanation': 'LLM explanation unavailable.',
            'fix': '',
            'severity': severity,   # fall back to static analysis severity
            'severity_reason': '',
            'raw': ''
        }


def _parse_llm_response(raw: str) -> dict:
    """
    Parse the structured LLM response into fields.
    Falls back gracefully if the model doesn't follow the format exactly.
    """
    result = {
        'explanation': '',
        'fix': '',
        'severity': '',
        'severity_reason': '',
        'raw': raw
    }

    # Split on section headers
    sections = {
        'EXPLANATION': '',
        'FIX': '',
        'SEVERITY': '',
        'REASON FOR SEVERITY': ''
    }

    current_section = None
    for line in raw.splitlines():
        stripped = line.strip()

        # Detect section headers
        matched = False
        for key in sections:
            if stripped.startswith(f"{key}:"):
                current_section = key
                # Grab inline content after the colon if any
                inline = stripped[len(key)+1:].strip()
                if inline:
                    sections[key] += inline + '\n'
                matched = True
                break

        if not matched and current_section:
            sections[current_section] += line + '\n'

    result['explanation'] = sections['EXPLANATION'].strip()
    result['fix'] = sections['FIX'].strip()
    result['severity'] = sections['SEVERITY'].strip().upper()
    result['severity_reason'] = sections['REASON FOR SEVERITY'].strip()

    # Normalise severity — if LLM drifted, fall back to MEDIUM
    if result['severity'] not in ('LOW', 'MEDIUM', 'HIGH'):
        result['severity'] = 'MEDIUM'

    return result
def _parse_llm_response(raw: str) -> dict:
    result = {
        'explanation': '',
        'fix': '',
        'severity': '',
        'severity_reason': '',
        'raw': raw
    }

    sections = {
        'EXPLANATION': '',
        'FIX': '',
    }

    current_section = None
    for line in raw.splitlines():
        stripped = line.strip()

        matched = False
        for key in sections:
            if stripped.startswith(f"{key}:"):
                current_section = key
                inline = stripped[len(key)+1:].strip()
                if inline:
                    sections[key] += inline + '\n'
                matched = True
                break

        if not matched and current_section:
            sections[current_section] += line + '\n'

    result['explanation'] = sections['EXPLANATION'].strip()
    result['fix'] = sections['FIX'].strip()

    return result