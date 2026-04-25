import subprocess
import tempfile
import os
import re
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("nexops.compiler")


def _find_project_root() -> Path:
    """
    Directory that contains package.json (nexops-mcp root), not process cwd.
    Walks upward from this file so Render/cron jobs with arbitrary cwd still work.
    """
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        if (p / "package.json").is_file():
            return p
    # Fallback: src/services/compiler.py -> parents[2] == repo root
    return Path(__file__).resolve().parents[2]


def get_cashc_path() -> str:
    """
    Resolve cashc from project node_modules/.bin (pinned in package.json), not cwd.
    Windows uses cashc.cmd in .bin; Unix uses the shell shim `cashc`.
    """
    project_root = _find_project_root()
    bin_dir = project_root / "node_modules" / ".bin"
    if os.name == "nt":
        for name in ("cashc.cmd", "cashc.exe", "cashc"):
            p = bin_dir / name
            if p.is_file():
                return str(p)
        appdata = os.environ.get("APPDATA", "")
        npm_global = os.path.join(appdata, "npm", "cashc.cmd")
        if os.path.isfile(npm_global):
            return npm_global
    else:
        p = bin_dir / "cashc"
        if p.is_file():
            return str(p)
    return "cashc"


def _parse_cashc_error(stderr: str) -> dict:
    """
    Parse raw cashc stderr into structured JSON.
    Returns dict with:
        type
        line
        token (optional)
        hint
        raw
    """
    error = {
        "type": "UnknownError",
        "line": None,
        "token": None,
        "hint": "",
        "raw": stderr.strip()
    }

    if not stderr.strip():
        return error

    # Internal cashc/Node crash — not a CashScript syntax failure
    if "sourceTags is not iterable" in stderr:
        return {
            "type": "ToolchainError",
            "line": None,
            "token": None,
            "hint": (
                "Internal cashc/Node error (not a contract syntax issue). "
                "Reinstall dependencies (npm ci), align Node with package.json engines, "
                "and ensure the server uses node_modules/.bin/cashc."
            ),
            "raw": stderr.strip(),
        }

    # Unused variable
    m = re.search(r"Unused variable (\w+)", stderr)
    if m:
        error.update({
            "type": "UnusedVariableError",
            "token": m.group(1),
            "hint": f"Remove unused variable '{m.group(1)}' or use it in require()"
        })
        return error

    # Parse line number (try multiple patterns)
    m = re.search(r"[Ll]ine (\d+)", stderr)
    if m:
        error["line"] = int(m.group(1))

    # Token recognition error
    m = re.search(r"Token recognition error at '([^']+)'", stderr)
    if m:
        error.update({
            "type": "ParseError",
            "token": m.group(1),
            "hint": f"Unexpected token near '{m.group(1)}'"
        })
        return error

    # Extraneous input
    m = re.search(r"Extraneous input '([^']+)'", stderr)
    if m:
        error.update({
            "type": "ExtraneousInputError",
            "token": m.group(1),
            "hint": f"Unexpected token '{m.group(1)}'"
        })
        return error

    # Type mismatch
    if "cannot be assigned" in stderr:
        error.update({
            "type": "TypeMismatchError",
            "hint": "Type mismatch — check bytes vs bytes32 or int usage"
        })
        return error

    return error


class CompilerService:
    """
    Phase 2C: Compile Gate
    Wraps cashc to validate syntactic correctness.
    """

    @staticmethod
    def compile(code: str) -> Dict[str, Any]:
        """
        Run cashc compiler on the provided code.

        Returns:
            success=True:  {"success": True, "error": None, "hex": str, "toolchain_error": False}
            success=False: {"success": False, "error": <structured dict>, "hex": None,
                            "toolchain_error": bool}
        """
        with tempfile.NamedTemporaryFile(suffix=".cash", delete=False, mode='w', encoding='utf-8') as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            cmd = get_cashc_path()
            logger.debug("[compiler] using cashc at: %s", cmd)

            # shell=True only when falling back to bare "cashc" on PATH (Windows quirk)
            use_shell = os.name == "nt" and cmd == "cashc"
            result = subprocess.run(
                [cmd, tmp_path, "--hex"],
                capture_output=True,
                text=True,
                shell=use_shell,
                timeout=10
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "error": None,
                    "hex": result.stdout.strip(),
                    "toolchain_error": False,
                }
            else:
                # Node may print crashes on stdout or stderr
                combined = (result.stderr or "") + "\n" + (result.stdout or "")
                parsed = _parse_cashc_error(combined)
                is_toolchain = parsed.get("type") == "ToolchainError"
                return {
                    "success": False,
                    "error": parsed,
                    "hex": None,
                    "toolchain_error": is_toolchain,
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": {
                    "type": "TimeoutError",
                    "line": None,
                    "token": None,
                    "hint": "Compiler timeout — code may be too large or hang on recursion",
                    "raw": "Compiler timeout"
                },
                "hex": None,
                "toolchain_error": False,
            }
        except FileNotFoundError:
            logger.error("cashc not found in PATH")
            return {
                "success": False,
                "error": {
                    "type": "CompilerNotFoundError",
                    "line": None,
                    "token": None,
                    "hint": "cashc is not installed or not in PATH",
                    "raw": "cashc compiler not installed or not in PATH"
                },
                "hex": None,
                "toolchain_error": False,
            }
        except Exception as e:
            logger.exception("Unexpected error during compilation")
            return {
                "success": False,
                "error": {
                    "type": "InternalError",
                    "line": None,
                    "token": None,
                    "hint": str(e),
                    "raw": str(e)
                },
                "hex": None,
                "toolchain_error": False,
            }
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


def get_compiler_service() -> CompilerService:
    return CompilerService()
