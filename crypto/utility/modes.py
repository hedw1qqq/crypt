from enum import Enum, auto


class CipherMode(Enum):
    ECB = auto()
    CBC = auto()
    PCBC = auto()
    CFB = auto()
    OFB = auto()
    CTR = auto()
    RANDOM_DELTA = auto()


class PaddingMode(Enum):
    ZEROS = auto()
    ANSI_X923 = auto()
    PKCS7 = auto()
    ISO_10126 = auto()
