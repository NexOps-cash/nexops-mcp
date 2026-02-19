import subprocess
import tempfile
import os
import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("nexops.compiler")


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
            success=True:  {"success": True, "error": None, "hex": str}
            success=False: {"success": False, "error": <structured dict>, "hex": None}
        """
        with tempfile.NamedTemporaryFile(suffix=".cash", delete=False, mode='w', encoding='utf-8') as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            cmd = "cashc"
            if os.name == 'nt':
                appdata = os.environ.get('APPDATA', '')
                npm_path = os.path.join(appdata, 'npm', 'cashc.cmd')
                if os.path.exists(npm_path):
                    cmd = npm_path

            result = subprocess.run(
                [cmd, tmp_path, "--hex"],
                capture_output=True,
                text=True,
                shell=(os.name == 'nt'),
                timeout=10
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "error": None,
                    "hex": result.stdout.strip()
                }
            else:
                parsed = _parse_cashc_error(result.stderr or "")
                return {
                    "success": False,
                    "error": parsed,
                    "hex": None
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
                "hex": None
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
                "hex": None
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
                "hex": None
            }
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


def get_compiler_service() -> CompilerService:
    return CompilerService()
