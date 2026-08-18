class OriginError(Exception):
    """Base error for ISQL Origin prototype runtime."""


class OriginDecodeError(OriginError):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}" if message else code)
