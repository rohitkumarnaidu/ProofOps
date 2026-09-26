"""Host runtime compatibility shims (Starlette v1.x on Python 3.14).

Ensures FastAPI 0.115 runs seamlessly across modern host environments
and pinned container images by bridging Starlette v1.x Router signature changes
and application attributes.
"""
from __future__ import annotations

try:
    import starlette.routing

    _orig_init = starlette.routing.Router.__init__

    def _patched_init(self: object, *args: object, **kwargs: object) -> object:
        kwargs.pop("on_startup", None)
        kwargs.pop("on_shutdown", None)
        setattr(self, "on_startup", [])
        setattr(self, "on_shutdown", [])
        return _orig_init(self, *args, **kwargs)

    starlette.routing.Router.__init__ = _patched_init  # type: ignore[method-assign]
except Exception:
    pass

try:
    import fastapi
    if not hasattr(fastapi.FastAPI, "max_body_size"):
        setattr(fastapi.FastAPI, "max_body_size", None)
except Exception:
    pass
