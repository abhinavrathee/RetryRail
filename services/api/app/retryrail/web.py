"""Fail-closed serving for the compiled reviewer-facing single-page app."""

from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse

_RESERVED_FIRST_SEGMENTS = frozenset(
    {"api", "docs", "health", "metrics", "openapi.json", "redoc", "v1"}
)


def install_compiled_web(application: FastAPI, dist_path: Path) -> None:
    """Serve hashed assets and fall back to the SPA only for UI routes."""

    try:
        root = dist_path.resolve(strict=True)
    except OSError as error:
        msg = f"compiled web directory is unavailable: {dist_path}"
        raise RuntimeError(msg) from error
    index = root / "index.html"
    if not root.is_dir() or not index.is_file():
        msg = f"compiled web index is unavailable: {index}"
        raise RuntimeError(msg)

    @application.api_route(
        "/{requested_path:path}",
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )
    async def compiled_web(requested_path: str) -> FileResponse:
        first_segment = requested_path.partition("/")[0]
        if first_segment in _RESERVED_FIRST_SEGMENTS:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        segments = tuple(segment for segment in requested_path.split("/") if segment)
        if any(segment.startswith(".") for segment in segments):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        candidate = (root / requested_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from error
        if candidate.is_file():
            cache_control = (
                "public, max-age=31536000, immutable"
                if first_segment == "assets"
                else "no-store"
            )
            return FileResponse(candidate, headers={"Cache-Control": cache_control})
        if candidate.suffix:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return FileResponse(index, media_type="text/html", headers={"Cache-Control": "no-store"})
