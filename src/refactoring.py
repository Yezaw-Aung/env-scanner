import re
from pathlib import Path

# Language rules for supported file extensions
LANGUAGE_RULES = {
    '.py': {
        'template': "os.environ.get('{var_name}')",
        'import_check': r"import\s+os\b|from\s+os\s+import",
        'import_add': "import os\n"
    },
    '.js':  {'template': "process.env.{var_name}", 'import_check': None, 'import_add': None},
    '.jsx': {'template': "process.env.{var_name}", 'import_check': None, 'import_add': None},
    '.ts':  {'template': "process.env.{var_name}", 'import_check': None, 'import_add': None},
    '.tsx': {'template': "process.env.{var_name}", 'import_check': None, 'import_add': None}
}

def inject_python_import(content: str) -> str:
    """Prepend 'import os' to Python file content, respecting shebangs and coding comments."""
    # Check if os is already imported
    if re.search(LANGUAGE_RULES['.py']['import_check'], content):
        return content
        
    lines = content.splitlines(keepends=True)
    insert_idx = 0
    
    # Traverse to find the first line after shebang or encoding comment
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#!') or stripped.startswith('# -*-') or stripped.startswith('# coding:'):
            insert_idx = i + 1
        elif not stripped:
            # Skip empty leading lines
            if insert_idx == i:
                insert_idx = i + 1
        else:
            break
            
    # Insert 'import os' with a newline
    lines.insert(insert_idx, "import os\n")
    return "".join(lines)

def append_to_env(env_path: Path, var_name: str, secret_val: str) -> None:
    """Append the key-value pair to the specified .env file."""
    try:
        env_path = Path(env_path).resolve()
        env_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Escape double quotes and backslashes for standard .env formatting
        escaped_val = secret_val.replace('\\', '\\\\').replace('"', '\\"')
        line_to_append = f'{var_name}="{escaped_val}"\n'
        
        content = ""
        if env_path.exists():
            content = env_path.read_text(encoding='utf-8', errors='ignore')
            
        # Check if the exact key-value pair is already defined in the .env
        # to avoid duplicate appends on repeated runs
        already_exists = False
        for line in content.splitlines():
            if line.strip() == f'{var_name}="{escaped_val}"':
                already_exists = True
                break
                
        if not already_exists:
            # Check if we need to write a leading newline if file exists and has content
            needs_leading_newline = content != "" and not content.endswith('\n')
            with env_path.open('a', encoding='utf-8') as f:
                if needs_leading_newline:
                    f.write('\n')
                f.write(line_to_append)
    except Exception as e:
        raise IOError(f"Failed to write to .env file: {e}")

def refactor_file(file_path: Path, match_text: str, var_name: str) -> bool:
    """Replace target secret match_text with the corresponding environment variable access statement."""
    try:
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            return False
            
        suffix = file_path.suffix.lower()
        if suffix not in LANGUAGE_RULES:
            return False
            
        rule = LANGUAGE_RULES[suffix]
        replacement = rule['template'].format(var_name=var_name)
        
        content = file_path.read_text(encoding='utf-8')
        if match_text not in content:
            return False
            
        new_content = content.replace(match_text, replacement)
        
        # Inject imports for Python if necessary
        if suffix == '.py':
            new_content = inject_python_import(new_content)
            
        file_path.write_text(new_content, encoding='utf-8')
        return True
    except Exception as e:
        raise IOError(f"Failed to refactor file {file_path}: {e}")
