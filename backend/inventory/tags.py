"""Tag endpoints/inputs for 2-2 prioritization."""

from __future__ import annotations

import re

from inventory.schema import Endpoint, InputParam

PATH_LIKE_NAMES = re.compile(
    r"(path|file|filename|filepath|template|dir|folder|export|download|attach|storage|uri|location|key)",
    re.IGNORECASE,
)

PATH_LIKE_PATH = re.compile(
    r"(download|export|file|attach|report|template)",
    re.IGNORECASE,
)


def tag_input(param: InputParam) -> list[str]:
    tags: list[str] = []
    if param.role in ("auth", "meta"):
        return tags
    if PATH_LIKE_NAMES.search(param.name):
        tags.append("2-2-candidate")
    if param.in_ == "path":
        tags.append("2-2-candidate")
    return tags


def tag_endpoint(endpoint: Endpoint) -> None:
    tags: set[str] = set(endpoint.tags)
    if PATH_LIKE_PATH.search(endpoint.path):
        tags.add("2-2-candidate")
    for inp in endpoint.inputs:
        for t in tag_input(inp):
            tags.add(t)
            if t not in inp.sources:
                pass
    endpoint.tags = sorted(tags)
