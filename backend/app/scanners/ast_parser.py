"""

scanners/ast_parser.py



Parses source code files into a structured JSON representation.



For Python: uses the built-in `ast` module (real AST parsing).

For JavaScript and Go: uses regex-based structural extraction

(a real AST would need extra dependencies like esprima/tree-sitter —

regex gets us 80% of the value for Day 3 with zero extra installs).



Output shape (same for all languages) so the rest of the pipeline

doesn't care which language it's looking at:



{

    "file": "app.py",

    "language": "python",

    "functions": [

        {

            "name": "search_user",

            "line": 42,

            "inputs": ["user_id"],

            "has_db_query": true,

            "validation": "none"

        }

    ],

    "imports": ["flask", "mysql"],

    "db_queries": [...],

    "api_calls": [...],

    "auth_logic": [...],

    "validation_points": [...]

}

"""



import ast

import re

import logging

from typing import Optional



logger = logging.getLogger("shieldlabs.ast_parser")





# ─────────────────────────────────────────────

# KEYWORDS USED TO DETECT PATTERNS

# ─────────────────────────────────────────────



# If a function body contains any of these substrings, we flag it as

# "has_db_query". This is intentionally simple at this stage — Day 4's

# pattern_detector.py will do the precise vulnerability matching.

DB_QUERY_KEYWORDS = [

    "SELECT", "INSERT", "UPDATE", "DELETE", "execute(", "cursor.",

    "session.query", ".query(", "db.execute"

]



AUTH_KEYWORDS = [

    "login", "authenticate", "verify_password", "check_password",

    "jwt.encode", "jwt.decode", "session[", "current_user",

    "@login_required", "@jwt_required"

]



VALIDATION_KEYWORDS = [

    "validate", "sanitize", "escape", "isinstance(", "re.match",

    "pydantic", "schema.validate", "clean("

]



API_CALL_KEYWORDS = [

    "requests.get", "requests.post", "httpx.", "fetch(", "axios.",

    "urllib.request"

]





# ─────────────────────────────────────────────

# PYTHON PARSER (real AST)

# ─────────────────────────────────────────────



def parse_python_file(file_path: str) -> dict:

    """

    Parse a Python file using the real `ast` module.



    Args:

        file_path: Path to the .py file



    Returns:

        Structured dict describing the file's functions, imports,

        and security-relevant patterns.

    """

    logger.info(f"Parsing Python file: {file_path}")



    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

        source = f.read()



    try:

        tree = ast.parse(source, filename=file_path)

    except SyntaxError as e:

        # If the file has a syntax error, we can't AST-parse it.

        # Return a minimal result instead of crashing the whole scan.

        logger.warning(f"Syntax error in {file_path}: {e}")

        return {

            "file": file_path,

            "language": "python",

            "functions": [],

            "imports": [],

            "db_queries": [],

            "api_calls": [],

            "auth_logic": [],

            "validation_points": [],

            "parse_error": str(e)

        }



    imports = []

    functions = []



    # ast.walk() goes through EVERY node in the tree, nested or not.

    # We look for two node types: imports and function definitions.

    for node in ast.walk(tree):



        # ── IMPORTS ──

        if isinstance(node, ast.Import):

            # Handles: import flask, import os

            for alias in node.names:

                imports.append(alias.name)



        elif isinstance(node, ast.ImportFrom):

            # Handles: from flask import Flask

            if node.module:

                imports.append(node.module)



        # ── CLASS DEFINITIONS ──
        elif isinstance(node, ast.ClassDef):
            classes.append({
                "name": node.name,
                "line": node.lineno,
                "end_line": node.end_lineno,
                "methods": [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            })

        # ── CLASS DEFINITIONS ──
        elif isinstance(node, ast.ClassDef):
            classes.append({
                "name": node.name,
                "line": node.lineno,
                "end_line": node.end_lineno,
                "methods": [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            })

        # ── FUNCTION DEFINITIONS ──

        elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):

            # Get the source code of just this function using line numbers

            func_lines = source.splitlines()[node.lineno - 1:node.end_lineno]

            func_source = "\n".join(func_lines)



            # Function parameter names (the "inputs")

            input_names = [arg.arg for arg in node.args.args]



            functions.append({

                "name": node.name,

                "line": node.lineno,

                "end_line": node.end_lineno,

                "inputs": input_names,

                "has_db_query": _contains_any(func_source, DB_QUERY_KEYWORDS),

                "has_auth_logic": _contains_any(func_source, AUTH_KEYWORDS),

                "has_api_call": _contains_any(func_source, API_CALL_KEYWORDS),

                "validation": "present" if _contains_any(func_source, VALIDATION_KEYWORDS) else "none",

                "source": func_source,

            })



    return {

        "file": file_path,

        "language": "python",

        "functions": functions,

        "imports": sorted(set(imports)),

        "db_queries": _find_lines_with(source, DB_QUERY_KEYWORDS),

        "api_calls": _find_lines_with(source, API_CALL_KEYWORDS),

        "auth_logic": _find_lines_with(source, AUTH_KEYWORDS),

        "validation_points": _find_lines_with(source, VALIDATION_KEYWORDS),

        "parse_error": None,

    }





# ─────────────────────────────────────────────

# JAVASCRIPT PARSER (regex-based structure)

# ─────────────────────────────────────────────



# Matches: function name(args) { ... }  OR  const name = (args) => { ... }

JS_FUNCTION_PATTERN = re.compile(

    r'(?:function\s+(\w+)\s*\(([^)]*)\)|'

    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>)',

)



JS_IMPORT_PATTERN = re.compile(

    r'(?:import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]|require\([\'"]([^\'"]+)[\'"]\))'

)





def parse_javascript_file(file_path: str) -> dict:

    """

    Parse a JavaScript/TypeScript file using regex.



    Not a real AST (would need esprima/tree-sitter), but extracts

    the same structural information we need for security scanning:

    function names, parameters, and lines, plus DB/API/auth patterns.



    Args:

        file_path: Path to the .js/.jsx/.ts/.tsx file



    Returns:

        Structured dict in the same shape as parse_python_file()

    """

    logger.info(f"Parsing JavaScript file: {file_path}")



    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

        source = f.read()



    lines = source.splitlines()

    functions = []



    for match in JS_FUNCTION_PATTERN.finditer(source):

        # Figure out which alternative matched (named function vs arrow function)

        name = match.group(1) or match.group(3) or "anonymous"

        args_str = match.group(2) or match.group(4) or ""

        input_names = [a.strip() for a in args_str.split(",") if a.strip()]



        # Find the line number by counting newlines before the match

        line_no = source[:match.start()].count("\n") + 1



        # Grab a rough function body: from match start to the next 40 lines

        # or end of file (good enough without a real brace-matching parser)

        end_line = min(line_no + 40, len(lines))

        func_source = "\n".join(lines[line_no - 1:end_line])



        functions.append({

            "name": name,

            "line": line_no,

            "end_line": end_line,

            "inputs": input_names,

            "has_db_query": _contains_any(func_source, DB_QUERY_KEYWORDS),

            "has_auth_logic": _contains_any(func_source, AUTH_KEYWORDS),

            "has_api_call": _contains_any(func_source, API_CALL_KEYWORDS),

            "validation": "present" if _contains_any(func_source, VALIDATION_KEYWORDS) else "none",

            "source": func_source,

        })



    imports = []

    for match in JS_IMPORT_PATTERN.finditer(source):

        imports.append(match.group(1) or match.group(2))



    return {

        "file": file_path,

        "language": "javascript",

        "functions": functions,

        "imports": sorted(set(imports)),

        "db_queries": _find_lines_with(source, DB_QUERY_KEYWORDS),

        "api_calls": _find_lines_with(source, API_CALL_KEYWORDS),

        "auth_logic": _find_lines_with(source, AUTH_KEYWORDS),

        "validation_points": _find_lines_with(source, VALIDATION_KEYWORDS),

        "parse_error": None,

    }





# ─────────────────────────────────────────────

# GO PARSER (regex-based structure)

# ─────────────────────────────────────────────



# Matches: func Name(args) returnType {

GO_FUNCTION_PATTERN = re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)')



GO_IMPORT_PATTERN = re.compile(r'"([^"]+)"')





def parse_golang_file(file_path: str) -> dict:

    """

    Parse a Go file using regex to extract function signatures.



    Args:

        file_path: Path to the .go file



    Returns:

        Structured dict in the same shape as parse_python_file()

    """

    logger.info(f"Parsing Go file: {file_path}")



    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

        source = f.read()



    lines = source.splitlines()

    functions = []



    for match in GO_FUNCTION_PATTERN.finditer(source):

        name = match.group(1)

        args_str = match.group(2)

        # Go args look like "userID string, name string" — grab just the names

        input_names = []

        for part in args_str.split(","):

            part = part.strip()

            if part:

                input_names.append(part.split(" ")[0])



        line_no = source[:match.start()].count("\n") + 1

        end_line = min(line_no + 40, len(lines))

        func_source = "\n".join(lines[line_no - 1:end_line])



        functions.append({

            "name": name,

            "line": line_no,

            "end_line": end_line,

            "inputs": input_names,

            "has_db_query": _contains_any(func_source, DB_QUERY_KEYWORDS),

            "has_auth_logic": _contains_any(func_source, AUTH_KEYWORDS),

            "has_api_call": _contains_any(func_source, API_CALL_KEYWORDS),

            "validation": "present" if _contains_any(func_source, VALIDATION_KEYWORDS) else "none",

            "source": func_source,

        })



    # Only pull imports from within an import ( ... ) block to avoid

    # matching every random quoted string in the file

    imports = []

    import_block_match = re.search(r'import\s*\(([^)]+)\)', source, re.DOTALL)

    if import_block_match:

        imports = GO_IMPORT_PATTERN.findall(import_block_match.group(1))



    return {

        "file": file_path,

        "language": "go",

        "functions": functions,

        "imports": sorted(set(imports)),

        "db_queries": _find_lines_with(source, DB_QUERY_KEYWORDS),

        "api_calls": _find_lines_with(source, API_CALL_KEYWORDS),

        "auth_logic": _find_lines_with(source, AUTH_KEYWORDS),

        "validation_points": _find_lines_with(source, VALIDATION_KEYWORDS),

        "parse_error": None,

    }





# ─────────────────────────────────────────────

# DISPATCHER — picks the right parser by extension

# ─────────────────────────────────────────────



EXTENSION_MAP = {

    ".py": parse_python_file,

    ".js": parse_javascript_file,

    ".jsx": parse_javascript_file,

    ".ts": parse_javascript_file,

    ".tsx": parse_javascript_file,

    ".go": parse_golang_file,

}





def parse_file(file_path: str) -> Optional[dict]:

    """

    Auto-detects the language from the file extension and calls

    the right parser. This is the function the rest of the app

    should use — it doesn't need to know which language it is.



    Args:

        file_path: Path to any supported source file



    Returns:

        Structured dict, or None if the extension isn't supported

    """

    for ext, parser_func in EXTENSION_MAP.items():

        if file_path.endswith(ext):

            return parser_func(file_path)



    logger.warning(f"Unsupported file extension, skipping: {file_path}")

    return None





# ─────────────────────────────────────────────

# HELPER FUNCTIONS

# ─────────────────────────────────────────────



def _contains_any(text: str, keywords: list[str]) -> bool:

    """Returns True if any keyword appears in the text (case-sensitive

    for code patterns, since e.g. SELECT vs select matters less but

    function names are case-sensitive)."""

    return any(keyword in text for keyword in keywords)





def _find_lines_with(source: str, keywords: list[str]) -> list[dict]:

    """

    Scans every line of source code and returns the ones containing

    any of the given keywords, along with their line number.



    Used to build the db_queries / api_calls / auth_logic / validation_points

    lists at the file level (not tied to a specific function).

    """

    results = []

    for i, line in enumerate(source.splitlines(), start=1):

        if _contains_any(line, keywords):

            results.append({

                "line": i,

                "code": line.strip()

            })

    return results