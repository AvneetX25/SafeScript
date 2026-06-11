# scanner/llm_explainer.py

import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

_client = None

def _get_client() -> Groq:
    """Lazy-init the Groq client so import doesn't fail if key is missing."""
    global _client
    if _client is None:
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            raise EnvironmentError(
                "GROQ_API_KEY not found in environment. "
                "Add it to your .env file."
            )
        _client = Groq(api_key=api_key)
    return _client


PROMPT_TEMPLATE = """You are a security engineer reviewing code for vulnerabilities.

The following code chunk has been flagged by static analysis tools.
Suspected vulnerability type: {vuln_type}
Static analysis message: {static_message}
Confidence score from ML classifier: {confidence}

Code:
Respond with exactly this structure — no extra text:

EXPLANATION:
(2-3 sentences explaining why this is dangerous and how it could be exploited)

FIX:
SEVERITY: LOW | MEDIUM | HIGH

Be specific to this exact code. No generic advice."""


def explain_vulnerability(
    code: str,
    vuln_type: str,
    static_message: str = "",
    confidence: float = 0.0
) -> dict:
    """
    Send a flagged code chunk to Groq LLM and get explanation + fix.

    Returns:
        {
            'explanation': str,
            'fix': str,
            'severity': str,
            'raw': str          # full LLM response for debugging
        }
    """
    client = _get_client()

    prompt = PROMPT_TEMPLATE.format(
        code=code,
        vuln_type=vuln_type,
        static_message=static_message,
        confidence=confidence
    )

    try:
        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=800,
            temperature=0.2       # low temp = consistent, factual output
        )
        raw = response.choices[0].message.content
        return _parse_llm_response(raw)

    except Exception as e:
        return {
            'explanation': f'LLM call failed: {str(e)}',
            'fix': '',
            'severity': 'UNKNOWN',
            'raw': ''
        }


def _parse_llm_response(raw: str) -> dict:
    """
    Parse the structured LLM response into fields.
    Gracefully handles cases where the model doesn't follow format exactly.
    """
    result = {
        'explanation': '',
        'fix': '',
        'severity': 'UNKNOWN',
        'raw': raw
    }

    # Extract EXPLANATION
    if 'EXPLANATION:' in raw:
        after = raw.split('EXPLANATION:', 1)[1]
        # Take everything until FIX: or end
        explanation_block = after.split('FIX:', 1)[0].strip()
        result['explanation'] = explanation_block

    # Extract FIX (inside code block)
    if '```' in raw:
        parts = raw.split('```')
        # parts[1] is the first code block content
        if len(parts) >= 3:
            # strip language tag if present (e.g. ```python)
            fix_raw = parts[1]
            first_line = fix_raw.split('\n', 1)
            if len(first_line) > 1 and first_line[0].strip().isalpha():
                result['fix'] = first_line[1].strip()
            else:
                result['fix'] = fix_raw.strip()

    # Extract SEVERITY
    for level in ('HIGH', 'MEDIUM', 'LOW'):
        if f'SEVERITY: {level}' in raw or raw.strip().endswith(level):
            result['severity'] = level
            break

    return result