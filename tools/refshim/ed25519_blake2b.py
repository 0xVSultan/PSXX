"""Stand-in for the sdist-only `ed25519-blake2b` (Nano curve): importable, unusable. We never use that curve."""
class VerifyingKey:
    def __init__(self, *a, **k): raise NotImplementedError
class SigningKey:
    def __init__(self, *a, **k): raise NotImplementedError
