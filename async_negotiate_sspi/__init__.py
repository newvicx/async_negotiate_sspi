from anyio.streams.tls import TLSAttribute, TLSStream
from httpcore.backends.asyncio import AsyncIOStream

from .negotiate import NegotiateAuth

# Monkey patch AsnycIO and Trio Streams to expose peercert
orig_AsyncIOStream__init__ = AsyncIOStream.__init__

def new_AsyncIOStream__init__(self, *args, **kwargs):
    orig_AsyncIOStream__init__(self, *args, **kwargs)
    if isinstance(self._stream, TLSStream):
        self.peercert = self._stream.extra_attributes.get(TLSAttribute.peer_certificate_binary)()

AsyncIOStream.__init__ = new_AsyncIOStream__init__

try:
    from httpcore.backends.trio import TrioStream

    orig_TrioStream__init__ = TrioStream.__init__

    def new_TrioStream__init__(self, *args, **kwargs):
        orig_TrioStream__init__(self, *args, **kwargs)
        if isinstance(self._stream, TLSStream):
            self.peercert = self._stream.extra_attributes.get(TLSAttribute.peer_certificate_binary)()

    TrioStream.__init__ = new_TrioStream__init__
except (ImportError, ModuleNotFoundError):
    pass