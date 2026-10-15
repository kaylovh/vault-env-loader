"""Write the GitHub release notes for one package version to stdout.

    python .github/release/notes.py node 0.1.1

Fills .github/release/<package>.md with the version and the matching
"## <version>" section of <package>/CHANGELOG.md. Fails if that section is
missing, so every release says what changed.
"""

import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
package, version = sys.argv[1], sys.argv[2]

with open(os.path.join(here, '%s.md' % package), encoding='utf-8') as f:
    template = f.read()
with open(os.path.join(here, '..', '..', package, 'CHANGELOG.md'), encoding='utf-8') as f:
    changelog = f.read()

m = re.search(r'^## %s\b[^\n]*\n(.*?)(?=^## |\Z)' % re.escape(version), changelog, re.M | re.S)
if not m or not m.group(1).strip():
    sys.exit('%s/CHANGELOG.md has no "## %s" section' % (package, version))

sys.stdout.write(template.replace('{{VERSION}}', version).replace('{{CHANGES}}', m.group(1).strip()))
