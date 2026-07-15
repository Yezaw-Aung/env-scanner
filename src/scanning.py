import math
import re
from collections import Counter
from pathlib import Path
from typing import Generator, Tuple, NamedTuple, List, Optional

# Scan for triple quotes, double quotes, single quotes, backticks
STRING_RE = re.compile(
    r'(?P<triple_double>"""(?:[^\\]|\\.)*?""")|'
    r"(?P<triple_single>'''(?:[^\\]|\\.)*?''')|"
    r'(?P<double>"(?:[^"\\]|\\.)*?")|'
    r"(?P<single>'(?:[^'\\]|\\.)*?')|"
    r'(?P<backtick>`(?:[^`\\]|\\.)*?`)',
    re.DOTALL
)

# Standard directory/file names to ignore
IGNORED_DIRS = {
    # Version control
    '.git', '.hg', '.svn',
    # Dependencies
    'node_modules', 'venv', '.venv', 'env', '.env',
    'vendor', 'bower_components', 'jspm_packages',
    # Build / output
    'dist', 'build', 'out', 'target', 'release',
    'bin', 'obj', '.next', '.nuxt', '.output',
    # Generated code
    'generated', '__generated__', 'gen',
    '.prisma',  # Prisma generated client
    # Caches & temp
    '.cache', 'cache', '.tmp', 'tmp', 'temp',
    '.turbo', '.gradle', '.parcel-cache',
    # Coverage / test artifacts
    'coverage', '.nyc_output',
    # Python artifacts
    '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
    # Misc
    '.idea', '.vscode',
}
IGNORED_FILES = {'.env', '.gitignore', 'LICENSE', 'package-lock.json', 'yarn.lock'}
# Common extensions to ignore
IGNORED_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz',
    '.exe', '.dll', '.so', '.dylib', '.woff', '.woff2', '.eot', '.ttf',
    '.mp4', '.mp3', '.wav', '.mov', '.avi', '.pyc', '.db', '.sqlite', '.txt', '.md',
    '.svg', '.avif', '.webp', '.bmp', '.tiff',  # image/asset formats
    '.lock', '.map', '.lockb',  # lockfiles & source maps
}

# ---------------------------------------------------------------------------
# Known secret indicators
# ---------------------------------------------------------------------------
# Real-world secrets are almost always short, single-line, and free of
# whitespace. These bounds are only applied to the *entropy* heuristic — the
# more precise `pattern` (variable name) and `value_pattern` (credential
# format) detectors still run on every string.
MAX_ENTROPY_LEN = 200        # credentials longer than this are exceedingly rare
MAX_SPACE_RATIO = 0.15       # >15% spaces => natural language / prose

# Substrings that, when present in a variable name (case-insensitive),
# strongly suggest the assigned value is a secret/credential. We use
# boundary-aware fragments (e.g. '_pass' / 'pass_') to avoid noisy matches
# on words like 'passenger', 'bypass', 'compass'.
SECRET_NAME_KEYWORDS = (
    'secret', 'token', 'password', 'passwd', 'pwd',
    '_pass', 'pass_',
    'api_key', 'apikey', 'api-key',
    'access_key', 'accesskey', 'access-key',
    'private_key', 'privatekey', 'private-key',
    'aws_secret', 'aws_access',
    'jwt', 'jws', 'jwk',
    'stripe', 'github_token', 'gitlab_token',
    'openai', 'anthropic', 'huggingface',
    'slack', 'sendgrid', 'twilio', 'mailgun',
    'encryption_key', 'signing_key', 'sign_key',
    'auth_token', 'auth_key', 'client_secret',
    'refresh_token', 'access_token', 'bearer',
    'credential', 'connection_string', 'conn_str',
    'database_url', 'db_url', 'redis_url', 'mongo_url', 'mongodb_url',
)

# Variable names that are definitely NOT secrets. When the string is assigned
# to one of these names, the noisy entropy heuristic is suppressed (the more
# precise value-pattern detector still runs, so a real AWS key accidentally
# stored in `style` would still be caught).
NON_SECRET_VAR_NAMES = {
    # CSS / styling
    'classname', 'class', 'style', 'styles', 'css', 'classes',
    'sx', 'tw', 'tailwind', 'stylesheet',
    'variant', 'size', 'theme', 'color', 'colorvalue',
    'fill', 'stroke', 'opacity', 'transform',
    'width', 'height', 'viewbox', 'd', 'x', 'y', 'cx', 'cy', 'r',
    # Responsive variant props (Tailwind)
    'sm', 'md', 'lg', 'xl', 'xs',
}

# Regex patterns matched against the *value* (inner_value) to detect
# well-known credential formats regardless of the surrounding variable name.
SECRET_VALUE_PATTERNS: List[Tuple['re.Pattern', str]] = [
    (re.compile(r'^AKIA[0-9A-Z]{16}$'), 'AWS Access Key ID'),
    (re.compile(r'^ASIA[0-9A-Z]{16}$'), 'AWS STS Access Key ID'),
    (re.compile(r'^sk_live_[A-Za-z0-9]{20,}$'), 'Stripe Live Secret Key'),
    (re.compile(r'^sk_test_[A-Za-z0-9]{20,}$'), 'Stripe Test Secret Key'),
    (re.compile(r'^pk_live_[A-Za-z0-9]{20,}$'), 'Stripe Live Publishable Key'),
    (re.compile(r'^pk_test_[A-Za-z0-9]{20,}$'), 'Stripe Test Publishable Key'),
    (re.compile(r'^gh[psu]_[A-Za-z0-9]{20,}$'), 'GitHub Token'),
    (re.compile(r'^xox[baprs]-[A-Za-z0-9-]+$'), 'Slack Token'),
    (re.compile(r'^AIza[0-9A-Za-z\-_]{35}$'), 'Google API Key'),
    (re.compile(r'^ya29\.[0-9A-Za-z\-_]+$'), 'Google OAuth Token'),
]

# ---------------------------------------------------------------------------
# Comment-style detection (so we can avoid flagging strings inside comments)
# ---------------------------------------------------------------------------
HASH_COMMENT_EXT = {'.py', '.sh', '.bash', '.zsh', '.rb', '.yml', '.yaml',
                    '.toml', '.conf', '.ini', '.cfg', '.r', '.pl', '.pm',
                    '.tf', '.hcl', '.nix', '.dockerfile'}
SLASH_COMMENT_EXT = {'.js', '.jsx', '.ts', '.tsx', '.go', '.rs', '.java',
                     '.c', '.cpp', '.h', '.hpp', '.swift', '.kt', '.kts',
                     '.css', '.scss', '.php', '.m', '.mm', '.scala', '.dart',
                     '.jsonc', '.cjs', '.mjs'}
HTML_COMMENT_EXT = {'.html', '.xml', '.svg', '.vue', '.xhtml'}
HASH_COMMENT_FILES = {'Dockerfile', 'Makefile', 'Gemfile', 'Rakefile',
                      'Vagrantfile', 'CMakeLists.txt'}


def get_comment_style(path: Path) -> Optional[str]:
    """Return the comment style for a given file: 'hash', 'slash', 'html', or None."""
    if path.name in HASH_COMMENT_FILES:
        return 'hash'
    suffix = path.suffix.lower()
    if suffix in HASH_COMMENT_EXT:
        return 'hash'
    if suffix in SLASH_COMMENT_EXT:
        return 'slash'
    if suffix in HTML_COMMENT_EXT:
        return 'html'
    return None


class SecretCandidate(NamedTuple):
    file_path: Path
    line_number: int
    match_text: str       # includes quotes (e.g. '"secret"')
    inner_value: str      # value inside quotes (e.g. 'secret')
    entropy: float
    # Why the candidate was flagged: 'entropy' | 'pattern' | 'value_pattern'
    reason: str = 'entropy'
    # Variable name the string was assigned to, if any (for display + suggestion)
    var_name: str = ''
    # Human-readable label when reason == 'value_pattern'
    pattern_label: str = ''
    # True if the string was found inside a comment
    in_comment: bool = False


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon Entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def get_line_number(content: str, start_index: int) -> int:
    """Calculate the line number (1-indexed) of a given index in the text."""
    return content.count('\n', 0, start_index) + 1


def _line_bounds(content: str, index: int) -> Tuple[int, int]:
    """Return (start, end) byte offsets of the line containing `index`."""
    start = content.rfind('\n', 0, index) + 1
    end = content.find('\n', index)
    if end == -1:
        end = len(content)
    return start, end


def _block_comment_ranges(content: str, style: Optional[str]) -> List[Tuple[int, int]]:
    """Return inclusive-exclusive (start, end) ranges of block comments in the file."""
    ranges: List[Tuple[int, int]] = []
    if style == 'slash':
        for m in re.finditer(r'/\*.*?\*/', content, re.DOTALL):
            ranges.append((m.start(), m.end()))
    elif style == 'html':
        for m in re.finditer(r'<!--.*?-->', content, re.DOTALL):
            ranges.append((m.start(), m.end()))
    return ranges


def _has_inline_comment_marker(before: str, marker: str) -> bool:
    """Return True if `marker` appears in `before` outside of any quoted string.

    Naive but effective: tracks simple single/double/backtick string state so
    that a '#' or '//' appearing inside a string literal is not mistaken for
    a comment marker.
    """
    i = 0
    in_str = None
    mlen = len(marker)
    while i < len(before):
        c = before[i]
        if in_str is not None:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'", '`'):
            in_str = c
            i += 1
            continue
        if before[i:i + mlen] == marker:
            return True
        i += 1
    return False


def _is_in_comment(content: str, match_start: int, style: Optional[str],
                   block_ranges: List[Tuple[int, int]]) -> bool:
    """Determine whether `match_start` lies inside a comment region."""
    if style is None:
        return False
    # Block comments (/* ... */, <!-- ... -->)
    for s, e in block_ranges:
        if s <= match_start < e:
            return True
    # Line comments (# ..., // ...)
    line_start, line_end = _line_bounds(content, match_start)
    line = content[line_start:line_end]
    stripped = line.lstrip()
    if style == 'hash':
        if stripped.startswith('#'):
            return True
        before = content[line_start:match_start]
        if _has_inline_comment_marker(before, '#'):
            return True
    elif style == 'slash':
        if stripped.startswith('//'):
            return True
        before = content[line_start:match_start]
        if _has_inline_comment_marker(before, '//'):
            return True
    return False


# Match an identifier (or quoted key) immediately preceding the string literal,
# accounting for TypeScript-style type annotations (`name: Type = ...`).
_TS_TYPED_ASSIGN_RE = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_][\w\[\]<>|,& .\-]*\s*=?\s*$'
)
_QUOTED_KEY_RE = re.compile(r'(?:"([^"]+)"|\'([^\']+)\')\s*:\s*$')
_PLAIN_ASSIGN_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*$')


def _extract_var_name(content: str, match_start: int) -> str:
    """Try to extract the variable name being assigned the string at `match_start`."""
    line_start, _ = _line_bounds(content, match_start)
    before = content[line_start:match_start]

    m = _TS_TYPED_ASSIGN_RE.search(before)
    if m:
        return m.group(1)
    m = _QUOTED_KEY_RE.search(before)
    if m:
        return m.group(1) or m.group(2) or ''
    m = _PLAIN_ASSIGN_RE.search(before)
    if m:
        return m.group(1)
    return ''


def _is_secret_var_name(name: str) -> bool:
    """Return True if the variable name looks like a secret/credential holder."""
    if not name:
        return False
    lower = name.lower()
    for kw in SECRET_NAME_KEYWORDS:
        if kw in lower:
            return True
    return False


def _match_secret_value_pattern(value: str) -> str:
    """Return a human-readable label if the value matches a known credential format."""
    for pattern, label in SECRET_VALUE_PATTERNS:
        if pattern.match(value):
            return label
    return ''


_CSS_DECL_RE = re.compile(r'^[\w-]+\s*:[^;{}]+(?:;\s*[\w-]+\s*:[^;{}]+)*;?\s*$')
# A Tailwind / utility-class list token: short, may contain - / : [ ] ( ) , % .
# A Tailwind / utility-class list token: short, may contain - / : [ ] ( ) , %
# . and arbitrary-value characters like = & * ' " ! + that appear inside
# bracketed segments such as [&:has(...)] or [class*='size-'].
_CLASS_TOKEN_RE = re.compile(r"^[A-Za-z0-9@:&\[\]()/.,%'\"_*=+!->]+$")


def _looks_like_css_or_classes(value: str) -> bool:
    """Return True for CSS declarations or utility-class lists (Tailwind, etc.)."""
    if not value:
        return False
    # CSS style attribute, e.g. "fill:#ede6ff;fill-opacity:1"
    if ';' in value and ':' in value and _CSS_DECL_RE.match(value):
        return True
    # Utility-class list, e.g. "flex items-center gap-2 rounded-md ..."
    tokens = value.split()
    if len(tokens) >= 3:
        if all(_CLASS_TOKEN_RE.match(t) for t in tokens):
            hyphenated = sum(1 for t in tokens if '-' in t)
            # Tailwind classes are heavily hyphenated; require at least half.
            if hyphenated >= len(tokens) // 2:
                return True
    return False


def _looks_like_non_secret_literal(value: str, var_name: str = '') -> bool:
    """Heuristic filter used to suppress entropy-based false positives.

    Returns True for strings that resemble prose, source code, templates, CSS,
    class lists, or local-URL boilerplate rather than credentials. The precise
    `pattern` (variable-name) and `value_pattern` (credential-format) detectors
    are NOT affected by this filter — only the noisy entropy fallback is.
    """
    if not value:
        return True
    # A non-secret variable name (className, style, css, ...) => skip entropy.
    if var_name and var_name.lower() in NON_SECRET_VAR_NAMES:
        return True
    # Multi-line strings (template literals, triple-quoted) are almost never
    # single secrets — they're system prompts, embedded code, SQL blocks, etc.
    if '\n' in value or '\r' in value:
        return True
    # Template interpolation => computed string, not a literal secret.
    if '${' in value:
        return True
    # Very long strings are usually prose, code, or data — not credentials.
    if len(value) > MAX_ENTROPY_LEN:
        return True
    # High whitespace ratio => natural language.
    if value.count(' ') / len(value) > MAX_SPACE_RATIO:
        return True
    # CSS declarations or Tailwind/utility class lists.
    if _looks_like_css_or_classes(value):
        return True
    # Localhost / loopback URLs are boilerplate, not secrets.
    low = value.lower()
    if low.startswith(('http://localhost', 'https://localhost',
                       'http://127.0.0.1', 'https://127.0.0.1',
                       'http://0.0.0.0', 'https://0.0.0.0',
                       'ws://localhost', 'wss://localhost')):
        return True
    return False


def extract_candidates(file_content: str, file_path: Path,
                       min_len: int = 8, threshold: float = 4.5
                       ) -> Generator[SecretCandidate, None, None]:
    """Find string literals that look like secrets in the file content.

    A string is flagged as a secret candidate when ANY of the following hold:
      1. Its Shannon entropy exceeds `threshold` (random-looking tokens).
      2. It is assigned to a variable whose name matches a known secret
         pattern (e.g. `AWS_SECRET_ACCESS_KEY`, `JWT_SECRET`, `DB_PASSWORD`).
      3. Its value matches a well-known credential format (e.g. AWS access
         key IDs `AKIA...`, Stripe keys `sk_live_...`, Slack tokens).

    Strings located inside comments (#, //, /* */, <!-- -->) are skipped.
    """
    style = get_comment_style(file_path)
    block_ranges = _block_comment_ranges(file_content, style)

    for match in STRING_RE.finditer(file_content):
        match_text = match.group(0)

        # Check if this string lives inside a comment region.
        in_comment = _is_in_comment(file_content, match.start(), style, block_ranges)

        # Determine the inner content depending on which quote style matched
        if match.lastgroup in ('triple_double', 'triple_single'):
            inner_value = match_text[3:-3]
        else:
            inner_value = match_text[1:-1]

        if len(inner_value) < min_len:
            continue

        var_name = _extract_var_name(file_content, match.start())
        entropy = calculate_entropy(inner_value)

        # Decide why this candidate is being flagged. Order matters: a
        # name-pattern hit is the most informative reason, then a known
        # value format, then plain high entropy.
        reason = ''
        label = ''
        if _is_secret_var_name(var_name):
            reason = 'pattern'
        else:
            label = _match_secret_value_pattern(inner_value)
            if label:
                reason = 'value_pattern'
            elif not in_comment and entropy > threshold and not _looks_like_non_secret_literal(inner_value, var_name):
                reason = 'entropy'

        if not reason:
            continue

        line_number = get_line_number(file_content, match.start())
        yield SecretCandidate(
            file_path=file_path,
            line_number=line_number,
            match_text=match_text,
            inner_value=inner_value,
            entropy=entropy,
            reason=reason,
            var_name=var_name,
            pattern_label=label,
            in_comment=in_comment,
        )


def should_ignore(path: Path) -> bool:
    """Check if file or directory should be ignored."""
    # Check if any parent part of the path is in the ignored list
    for part in path.parts:
        if part in IGNORED_DIRS:
            return True

    if path.name in IGNORED_FILES:
        return True

    if path.suffix.lower() in IGNORED_EXTENSIONS:
        return True

    return False


def scan_directory(dir_path: Path, min_len: int = 8, threshold: float = 4.5
                   ) -> Generator[SecretCandidate, None, None]:
    """Recursively scan a directory for files containing secret candidates."""
    try:
        # Resolve path to be absolute
        abs_dir = Path(dir_path).resolve()
        if not abs_dir.exists():
            return

        # We walk files recursively
        for path in abs_dir.rglob('*'):
            if not path.is_file() or should_ignore(path):
                continue

            try:
                # Read content as UTF-8. Skip file if it fails to decode (likely binary).
                content = path.read_text(encoding='utf-8', errors='strict')
                yield from extract_candidates(content, path, min_len, threshold)
            except (UnicodeDecodeError, PermissionError, FileNotFoundError):
                # Gracefully skip files with reading issues
                continue
    except Exception:
        # Handle unexpected directory listing or walk exceptions gracefully
        return
