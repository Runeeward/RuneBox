#!/usr/bin/env python3
"""Pin a release's own images by digest.

Usage: pin-release-images.py DIGEST_DIR VALUES_YAML IMAGES_JSON

DIGEST_DIR holds one file per pushed image, named after the image, whose
content is its pinned reference (registry/name:tag@sha256:<digest>), as the
release workflow's manifest jobs record them. Writes IMAGES_JSON (every
image, by name) and points the Helm chart's own images at their digests.
"""

import json
import re
import sys
from pathlib import Path

PINNED = re.compile(r"^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")

# Chart value lines to rewrite: (image name, exact line, replacement prefix).
CHART = [
    ("runebox", '  digest: ""', "  digest: "),
    ("runebox-egress", '  image: ""  # egress', "  image: "),
    ("runebox-csi-directvolume", '    image: ""  # csi-directvolume', "    image: "),
]


def main(digest_dir: str, values: str, out: str) -> int:
    images = {}
    for f in sorted(Path(digest_dir).iterdir()):
        ref = f.read_text().strip()
        if not PINNED.match(ref):
            sys.exit(f"{f.name}: not a pinned reference: {ref!r}")
        images[f.name] = ref
    tags = {ref.split("@")[0].rsplit(":", 1)[1] for ref in images.values()}
    if len(tags) != 1:
        sys.exit(f"images carry different tags: {sorted(tags)}")

    text = Path(values).read_text()
    lines = text.split("\n")
    for name, line, prefix in CHART:
        if name not in images:
            sys.exit(f"no digest recorded for {name}")
        if lines.count(line) != 1:
            sys.exit(f"{values}: expected exactly one line {line!r}")
        ref = images[name]
        value = "sha256:" + ref.split("@sha256:")[1] if name == "runebox" else ref
        lines[lines.index(line)] = f'{prefix}"{value}"'
    Path(values).write_text("\n".join(lines))

    doc = {"version": tags.pop(), "images": images}
    Path(out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
