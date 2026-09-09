"""Apply independent request edits and retain only metadata about their outcome."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RewriteResult:
    applied: tuple[str, ...]
    failed: tuple[str, ...]

    @property
    def outcome(self) -> str:
        if self.failed:
            return "partial" if self.applied else "failed"
        return "applied" if self.applied else "unchanged"


def apply_rewrite(request, *, url, body, headers, new_url, new_body, new_headers) -> RewriteResult:
    """Verify request-object changes; this does not prove receiver delivery."""
    applied, failed = [], []

    def change(part, setter, verify):
        try:
            setter()
            if not verify():
                raise ValueError("request object did not retain the change")
        except Exception:
            # Never retain exception strings: setters can include raw URLs or
            # content-bearing values in their error message.
            failed.append(part)
        else:
            applied.append(part)

    if new_url != url:
        change("url", lambda: setattr(request, "url", new_url), lambda: request.url == new_url)
    if new_body is not None and new_body != body:
        encoded = new_body if isinstance(new_body, bytes) else str(new_body).encode("utf-8")
        change("body", lambda: request.set_content(encoded),
               lambda: getattr(request, "content", request.raw_content) == encoded)
    for name, value in new_headers.items():
        if headers.get(name) != value:
            # The outcome records the part, never an attacker-controlled name.
            change("header", lambda name=name, value=value: request.headers.__setitem__(name, value),
                   lambda name=name, value=value: request.headers.get(name) == value)
    return RewriteResult(tuple(applied), tuple(failed))
