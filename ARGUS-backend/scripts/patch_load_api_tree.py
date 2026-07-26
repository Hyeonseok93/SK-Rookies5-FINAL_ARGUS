"""One-off patch: replace duplicated load_api_tree / probe_base_url with shared imports."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LOAD_BLOCK = re.compile(
    r"\n\ndef load_api_tree\(data_dir[^\)]*\)[^\n]*\n(?:    [^\n]+\n)+?    return None\n",
    re.MULTILINE,
)

PROBE_BLOCK = re.compile(
    r"\n\ndef probe_base_url\(base_url: str\) -> str:\n(?:    [^\n]+\n)+?"
    r'    return f"\{scheme\}://\{probe_host\}\{port\}"\n',
    re.MULTILINE,
)


def patch_file(rel: str, *, need_probe: bool) -> None:
    p = ROOT / rel
    text = p.read_text(encoding="utf-8")
    orig = text
    text = LOAD_BLOCK.sub("\n", text)
    if need_probe:
        text = PROBE_BLOCK.sub("\n", text)
    if orig == text:
        print("skip", rel)
        return
    if "from inventory.load import load_api_tree" not in text:
        anchor = "from inventory."
        idx = text.find(anchor)
        if idx >= 0:
            line_end = text.find("\n", idx) + 1
            text = text[:line_end] + "from inventory.load import load_api_tree\n" + text[line_end:]
        else:
            text = "from inventory.load import load_api_tree\n" + text
    if need_probe and "from inventory.net import probe_base_url" not in text:
        idx = text.find("from inventory.load import load_api_tree\n")
        if idx >= 0:
            insert_at = idx + len("from inventory.load import load_api_tree\n")
            text = text[:insert_at] + "from inventory.net import probe_base_url\n" + text[insert_at:]
    p.write_text(text, encoding="utf-8")
    print("updated", rel)


def main() -> None:
    tree_only = [
        "diagnosis/modules/4-2/targets.py",
        "diagnosis/modules/6-1/targets.py",
        "diagnosis/modules/4-1/targets.py",
        "diagnosis/modules/3-4/targets.py",
        "diagnosis/modules/2-2/scanner.py",
        "app/services/login_discovery_service.py",
    ]
    with_probe = [
        "diagnosis/modules/3-6/targets.py",
        "diagnosis/modules/7-2/targets.py",
        "diagnosis/modules/5-2/targets.py",
        "diagnosis/modules/3-5/targets.py",
        "diagnosis/modules/7-1/targets.py",
        "diagnosis/modules/7-3/targets.py",
        "diagnosis/modules/7-4/targets.py",
    ]
    for rel in tree_only:
        patch_file(rel, need_probe=False)
    for rel in with_probe:
        patch_file(rel, need_probe=True)


if __name__ == "__main__":
    main()
