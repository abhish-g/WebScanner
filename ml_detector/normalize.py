"""
Text normalization for attack payloads.

IMPORTANT: This exact function must be used BOTH when training the
model and when serving predictions. If they differ, the model sees
different text at serve time than it was trained on and accuracy
silently collapses.
"""

import html
import unicodedata
from urllib.parse import unquote_plus

MAX_DECODE_PASSES = 3


def normalize(text: str) -> str:
    """Undo common evasion encodings before vectorizing.

    Attackers rarely send `<script>` in plain form. They send
    `%3Cscript%3E`, `&lt;script&gt;`, or mixed case. Without this,
    each variant looks like a completely different string to TF-IDF.
    """
    if not isinstance(text, str):
        return ""

    # Loop to handle double / triple encoding (%253C -> %3C -> <)
    previous = None
    for _ in range(MAX_DECODE_PASSES):
        if text == previous:
            break
        previous = text
        text = unquote_plus(text)

    text = html.unescape(text)

    # Fold unicode lookalikes (fullwidth chars, etc.) to ASCII forms
    text = unicodedata.normalize("NFKC", text)

    return text.lower().strip()
