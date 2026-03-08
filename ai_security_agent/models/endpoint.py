"""Endpoint discovery model."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EndpointMethod(str, Enum):
    """HTTP methods we consider for API endpoints."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class Endpoint(BaseModel):
    """Discovered API or web endpoint."""

    url: str
    method: EndpointMethod = EndpointMethod.GET
    source: str = Field(description="e.g. 'crawl', 'js_parse', 'pattern'")
    path_pattern: str | None = Field(
        default=None,
        description="Normalized pattern e.g. /api/user/{id}",
    )
    extra: dict[str, Any] = Field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.url, self.method))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Endpoint):
            return False
        return self.url == other.url and self.method == other.method
