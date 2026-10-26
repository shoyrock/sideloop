"""Read-only static checks; run from any directory with the dev environment."""

import os
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class InlineScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag != 'script':
            return
        attrs = dict(attrs)
        kind = (attrs.get('type') or '').strip().lower()
        if 'src' not in attrs and kind in (
            '',
            'text/javascript',
            'application/javascript',
            'module',
        ):
            self.current = (kind, [])

    def handle_data(self, data):
        if self.current is not None:
            self.current[1].append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.current is not None:
            kind, chunks = self.current
            self.scripts.append((kind, ''.join(chunks)))
            self.current = None


def main():
    bash = shutil.which('bash')
    if os.name == 'nt':
        # Prefer Git Bash to the Windows WSL launcher, which may have no distro.
        git_bash = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
        if git_bash.is_file():
            bash = str(git_bash)
    node = shutil.which('node')
    if not bash or not node:
        raise SystemExit('Static checks require Bash and Node.js; see docs/code-quality.md.')

    subprocess.run(
        [sys.executable, '-m', 'ruff', 'check', 'sideloop', 'scripts', 'tools', 'tests'],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [sys.executable, '-m', 'ruff', 'format', '--check', 'tools/check_quality.py'],
        cwd=ROOT,
        check=True,
    )

    shell_files = sorted((ROOT / 'scripts').rglob('*.sh')) + sorted((ROOT / 'tools').rglob('*.sh'))
    for path in shell_files:
        print(f'Bash syntax: {path.relative_to(ROOT)}', flush=True)
        subprocess.run(
            [bash, '-n'], input=path.read_text(encoding='utf-8').encode('utf-8'), check=True
        )

    for path in sorted((ROOT / 'sideloop').rglob('*.html')):
        parser = InlineScripts()
        parser.feed(path.read_text(encoding='utf-8'))
        parser.close()
        if parser.current is not None:
            raise SystemExit(f'{path.relative_to(ROOT)}: unclosed script tag')
        for number, (kind, source) in enumerate(parser.scripts, 1):
            print(f'JavaScript syntax: {path.relative_to(ROOT)}, script {number}', flush=True)
            mode = 'module' if kind == 'module' else 'commonjs'
            subprocess.run(
                [node, '--check', f'--input-type={mode}'], input=source.encode('utf-8'), check=True
            )

    print('Static quality checks passed. Run the relevant Linux regression tests separately.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
