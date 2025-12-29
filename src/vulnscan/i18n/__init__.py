"""
Internationalization module.
"""

from .zh_CN import MESSAGES as ZH_CN
from .en_US import MESSAGES as EN_US

LANGUAGES = {
    "zh_CN": ZH_CN,
    "en_US": EN_US,
}


def get_messages(lang: str = "zh_CN") -> dict:
    """Get messages for a specific language."""
    return LANGUAGES.get(lang, EN_US)


def translate(key: str, lang: str = "zh_CN") -> str:
    """Translate a single key."""
    messages = get_messages(lang)
    return messages.get(key, key)


__all__ = ["get_messages", "translate", "LANGUAGES"]
