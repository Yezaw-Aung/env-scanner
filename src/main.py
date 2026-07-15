import argparse
import sys
import re
import shutil
from pathlib import Path

from src.scanning import scan_directory, SecretCandidate
from src.refactoring import refactor_file, append_to_env, LANGUAGE_RULES

# ANSI escape codes for rich terminal styling
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}======================================================================
🛡️  ENV-GUARD: Cybersecurity Hardcoded Secret Scanner & Refactorer  🛡️
======================================================================{RESET}
"""

REASON_LABELS = {
    'entropy': 'High Shannon entropy',
    'pattern': 'Suspicious variable name',
    'value_pattern': 'Known credential format',
}


def clean_var_name(name: str) -> str:
    """Sanitize and format a variable name to uppercase snake_case."""
    cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', name.strip())
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned.upper()


def get_valid_var_name(suggestion: str = "") -> str:
    """Prompt the user for a valid environment variable name."""
    suggestion = clean_var_name(suggestion) if suggestion else ""
    while True:
        try:
            hint = f" (default: {suggestion})" if suggestion else " (e.g., API_KEY)"
            raw = input(f"{BOLD}Enter a descriptive variable name for this secret{hint}: {RESET}").strip()
            name = raw or suggestion
            if not name:
                print(f"{RED}Variable name cannot be empty. Please try again.{RESET}")
                continue
            cleaned = clean_var_name(name)
            if not re.match(r'^[A-Z_][A-Z0-9_]*$', cleaned):
                print(f"{RED}Invalid variable name format. Use letters, numbers, and underscores.{RESET}")
                continue
            return cleaned
        except (KeyboardInterrupt, EOFError):
            print(f"\n{RED}Operation cancelled by user.{RESET}")
            sys.exit(0)


def print_finding(candidate: SecretCandidate, target_dir: Path) -> None:
    """Print a styled warning for a single secret candidate."""
    reason_label = REASON_LABELS.get(candidate.reason, candidate.reason)
    print(f"{RED}{BOLD}[⚠️  CRITICAL]{RESET} Potential secret detected!")
    print(f"  {BOLD}File:{RESET} {CYAN}{candidate.file_path.relative_to(target_dir)}:{candidate.line_number}{RESET}")
    # Truncate very long match text for readability
    display = candidate.match_text
    if len(display) > 120:
        display = display[:117] + "..."
    print(f"  {BOLD}String:{RESET} {YELLOW}{display}{RESET}")
    print(f"  {BOLD}Entropy:{RESET} {candidate.entropy:.3f}")
    print(f"  {BOLD}Reason:{RESET} {reason_label}"
          + (f" ({candidate.pattern_label})" if candidate.pattern_label else ""))
    if candidate.in_comment:
        print(f"  {BOLD}In Comment:{RESET} {YELLOW}true{RESET} (secret is commented out but still committed to version control)")
    if candidate.var_name:
        print(f"  {BOLD}Variable:{RESET} {candidate.var_name}")


def run_scan_only(target_dir: Path, min_len: int, threshold: float) -> int:
    """Scan-only mode: print all findings without prompting or modifying files."""
    total = 0
    files_with_findings = set()

    for candidate in scan_directory(target_dir, min_len=min_len, threshold=threshold):
        total += 1
        files_with_findings.add(candidate.file_path)
        print_finding(candidate, target_dir)
        print()

    return total, len(files_with_findings)


def run_refactor_mode(target_dir: Path, env_path: Path, min_len: int, threshold: float):
    """Interactive refactor mode: prompt for each finding, refactor confirmed secrets."""
    resolved_secrets = {}   # inner_value -> var_name
    ignored_values = set()  # inner_values confirmed NOT to be secrets
    files_with_findings = set()
    total_findings = 0
    refactored_count = 0

    for candidate in scan_directory(target_dir, min_len=min_len, threshold=threshold):
        files_with_findings.add(candidate.file_path)
        total_findings += 1

        # Auto-refactor duplicates of already-confirmed secrets
        if candidate.inner_value in resolved_secrets:
            var_name = resolved_secrets[candidate.inner_value]
            suffix = candidate.file_path.suffix.lower()
            if suffix in LANGUAGE_RULES:
                try:
                    refactored = refactor_file(candidate.file_path, candidate.match_text, var_name)
                    if refactored:
                        print(f"{GREEN}[🔄 AUTO-REFACTOR]{RESET} Replaced duplicate secret in "
                              f"{CYAN}{candidate.file_path.relative_to(target_dir)}:{candidate.line_number}{RESET} "
                              f"with {BOLD}{var_name}{RESET}")
                        refactored_count += 1
                except Exception as e:
                    print(f"{RED}[⚠️  ERROR] Failed to auto-refactor duplicate secret: {e}{RESET}")
            continue

        if candidate.inner_value in ignored_values:
            continue

        print_finding(candidate, target_dir)
        suggested = clean_var_name(candidate.var_name) if candidate.var_name else ""

        while True:
            try:
                prompt = (f"{BOLD}Is this a secret credential? (y/n)"
                          + (f" [suggested: {suggested}]" if suggested else "")
                          + f": {RESET}")
                choice = input(prompt).strip().lower()
                if choice in ('y', 'yes'):
                    var_name = get_valid_var_name(suggested)

                    try:
                        append_to_env(env_path, var_name, candidate.inner_value)
                        resolved_secrets[candidate.inner_value] = var_name
                        print(f"{GREEN}[✓] Appended {BOLD}{var_name}{RESET} to {env_path.name}")
                    except Exception as e:
                        print(f"{RED}[⚠️  ERROR] Failed to write to .env: {e}{RESET}")
                        break

                    suffix = candidate.file_path.suffix.lower()
                    if suffix in LANGUAGE_RULES:
                        try:
                            refactored = refactor_file(candidate.file_path, candidate.match_text, var_name)
                            if refactored:
                                print(f"{GREEN}[✓] Successfully refactored source file.{RESET}\n")
                                refactored_count += 1
                            else:
                                print(f"{YELLOW}[!] Source file refactor skipped (matching token not found).{RESET}\n")
                        except Exception as e:
                            print(f"{RED}[⚠️  ERROR] Failed to refactor source file: {e}{RESET}\n")
                    else:
                        print(f"{YELLOW}[!] Auto-refactor not supported for extension '{suffix}'. Skipping file edit.{RESET}\n")
                    break

                elif choice in ('n', 'no'):
                    ignored_values.add(candidate.inner_value)
                    print(f"{BLUE}[-] Ignored candidate.{RESET}\n")
                    break
                else:
                    print(f"{RED}Invalid input. Please enter 'y' or 'n'.{RESET}")
            except (KeyboardInterrupt, EOFError):
                print(f"\n{RED}Scan aborted by user.{RESET}")
                sys.exit(0)

    return total_findings, len(files_with_findings), refactored_count, len(resolved_secrets)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="env-guard: Recursively scan a directory for hardcoded secrets. "
                    "By default runs in scan-only mode. Use --refactor to interactively "
                    "extract secrets into a .env file and refactor source code."
    )
    parser.add_argument(
        "directory",
        type=str,
        help="Path to the source directory to scan"
    )
    parser.add_argument(
        "-r", "--refactor",
        action="store_true",
        help="Enable interactive refactor mode: prompt for each finding, "
             "write confirmed secrets to .env, and replace them in source files."
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=4.5,
        help="Shannon Entropy threshold (default: 4.5)"
    )
    parser.add_argument(
        "-l", "--min-len",
        type=int,
        default=8,
        help="Minimum length of string literals to analyze (default: 8)"
    )
    parser.add_argument(
        "-e", "--env",
        type=str,
        default=None,
        help="Target .env file path (default: <target_dir>/.env, only used with --refactor)"
    )
    parser.add_argument(
        "-d", "--duplicate",
        action="store_true",
        help="Create a copy of the source directory (named <dir>_env_guard_fixed) "
             "and operate on the copy. Only meaningful with --refactor."
    )

    args = parser.parse_args()

    target_dir = Path(args.directory).resolve()
    if not target_dir.exists():
        print(f"{RED}{BOLD}Error:{RESET} Directory '{args.directory}' does not exist.")
        sys.exit(1)

    if not target_dir.is_dir():
        print(f"{RED}{BOLD}Error:{RESET} '{args.directory}' is not a directory.")
        sys.exit(1)

    # Warn if --duplicate is used without --refactor
    if args.duplicate and not args.refactor:
        print(f"{YELLOW}[!] --duplicate has no effect without --refactor (scan-only mode doesn't modify files).{RESET}\n")

    # Handle duplicating option (only relevant in refactor mode)
    if args.duplicate and args.refactor:
        base_dst = target_dir.parent / f"{target_dir.name}_env_guard_fixed"
        dst_dir = base_dst
        counter = 1
        while dst_dir.exists():
            dst_dir = target_dir.parent / f"{target_dir.name}_env_guard_fixed_{counter}"
            counter += 1

        print(f"{GREEN}[🔄 DUPLICATING]{RESET} Copying project directory to: {dst_dir}")
        try:
            shutil.copytree(target_dir, dst_dir)
            target_dir = dst_dir
        except Exception as e:
            print(f"{RED}{BOLD}Error duplicating directory:{RESET} {e}")
            sys.exit(1)

    # Determine .env destination path (only used in refactor mode)
    env_path = Path(args.env).resolve() if args.env else target_dir / ".env"

    # Print scan configuration
    mode_label = f"{MAGENTA}REFACTOR{RESET}" if args.refactor else f"{BLUE}SCAN-ONLY{RESET}"
    print(f"{BLUE}Mode:{RESET} {mode_label}")
    print(f"{BLUE}Target Directory:{RESET} {target_dir}")
    if args.refactor:
        print(f"{BLUE}Target .env File:{RESET} {env_path}")
    print(f"{BLUE}Entropy Threshold:{RESET} {args.threshold}")
    print(f"{BLUE}Min String Length:{RESET} {args.min_len}")
    print(f"{CYAN}Scanning files recursively...{RESET}\n")

    try:
        if args.refactor:
            total, files_count, refactored, secrets_added = run_refactor_mode(
                target_dir, env_path, args.min_len, args.threshold
            )
        else:
            total, files_count = run_scan_only(target_dir, args.min_len, args.threshold)
            refactored = 0
            secrets_added = 0
    except Exception as e:
        print(f"{RED}{BOLD}Critical error during scanning process:{RESET} {e}")
        sys.exit(1)

    # Print scan summary report
    print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
    print(f"{CYAN}{BOLD}SCAN COMPLETED{RESET}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}")
    print(f"🛡️  {BOLD}Mode:{RESET} {'Refactor' if args.refactor else 'Scan-only'}")
    print(f"📁 {BOLD}Files Scanned with Findings:{RESET} {files_count}")
    print(f"⚠️  {BOLD}Total Secret Candidates Flagged:{RESET} {total}")
    if args.refactor:
        print(f"🔄 {BOLD}Source Files Auto-Refactored:{RESET} {refactored}")
        print(f"🔑 {BOLD}Secrets Added to .env:{RESET} {secrets_added}")
    print(f"======================================================================")

if __name__ == "__main__":
    main()
