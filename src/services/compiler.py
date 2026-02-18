import subprocess
import tempfile
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("nexops.compiler")

class CompilerService:
    """
    Phase 2C: Compile Gate
    Wraps cashc to validate syntactic correctness.
    """

    @staticmethod
    def compile(code: str) -> Dict[str, Any]:
        """
        Run cashc compiler on the provided code.
        Returns result dict with: success (bool), error (str), artifacts (hex)
        """
        # Create a temporary .cash file
        with tempfile.NamedTemporaryFile(suffix=".cash", delete=False, mode='w', encoding='utf-8') as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            # Run cashc --hex
            # Note: We assume cashc is in the PATH. If not, this will fail.
            # Resolve cashc binary (PATH vs Absolute for Windows)
            cmd = "cashc"
            if os.name == 'nt':
                appdata = os.environ.get('APPDATA', '')
                npm_path = os.path.join(appdata, 'npm', 'cashc.cmd')
                if os.path.exists(npm_path):
                    cmd = npm_path
                elif not any(os.path.exists(os.path.join(p, 'cashc.exe')) or os.path.exists(os.path.join(p, 'cashc.cmd')) for p in os.environ.get('PATH', '').split(os.pathsep)):
                    # Last ditch effort: try shell=True for path resolution
                    pass

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
                return {
                    "success": False,
                    "error": result.stderr.strip() or "Unknown compiler error",
                    "hex": None
                }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Compiler timeout", "hex": None}
        except FileNotFoundError:
            logger.error("cashc not found in PATH")
            # In demo mode, we might want to mock success if cashc is missing?
            # For now, we return a clear error.
            return {"success": False, "error": "cashc compiler not installed or not in PATH", "hex": None}
        except Exception as e:
            logger.exception("Unexpected error during compilation")
            return {"success": False, "error": str(e), "hex": None}
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

def get_compiler_service() -> CompilerService:
    return CompilerService()
