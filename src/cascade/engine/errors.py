from __future__ import annotations


class DecodeError(ValueError):
    def __init__(self, message_fr: str, message_en: str) -> None:
        super().__init__(message_fr)
        self.message_fr = message_fr
        self.message_en = message_en

    def localized(self, lang: str) -> str:
        return self.message_en if lang == "en" else self.message_fr
