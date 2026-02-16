"""
Session Manager — In-memory conversation state store.

Stores SessionState per session_id. Supports get, create, and update.
"""

import uuid
import logging
from typing import Dict, Optional

from src.models import SessionState, TurnRecord, ContractIR, TollGateResult

logger = logging.getLogger("nexops.session")


class SessionManager:
    """In-memory session store. One session per conversation."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionState] = {}

    def create(self, session_id: Optional[str] = None) -> SessionState:
        """Create a new session. Returns the session."""
        sid = session_id or str(uuid.uuid4())
        session = SessionState(session_id=sid)
        self._sessions[sid] = session
        logger.info(f"Session created: {sid}")
        return session

    def get(self, session_id: str) -> Optional[SessionState]:
        """Get existing session by ID. Returns None if not found."""
        return self._sessions.get(session_id)

    def get_or_create(self, session_id: Optional[str] = None) -> SessionState:
        """Get existing session or create new one."""
        if session_id and session_id in self._sessions:
            return self._sessions[session_id]
        return self.create(session_id)

    def store_turn(
        self,
        session_id: str,
        intent: str,
        contract_ir: ContractIR,
        final_code: str,
        toll_gate_result: TollGateResult,
    ) -> None:
        """Record a completed generation turn in session history."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")

        turn_number = len(session.history) + 1
        record = TurnRecord(
            turn=turn_number,
            intent=intent,
            contract_ir=contract_ir,
            final_code=final_code,
            toll_gate_result=toll_gate_result,
        )
        session.history.append(record)
        session.current_contract = contract_ir
        session.current_code = final_code
        logger.info(f"Session {session_id}: turn {turn_number} stored")

    def delete(self, session_id: str) -> bool:
        """Delete a session. Returns True if it existed."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"Session deleted: {session_id}")
            return True
        return False


# Singleton
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the singleton SessionManager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
