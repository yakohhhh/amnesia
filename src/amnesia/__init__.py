"""amnesia — audit de la couverture de logs avant l'incident."""

__version__ = "0.1.0.dev0"

# apres __version__, que le moteur reprend dans AuditResult
from .runner import AuditResult, AuditSummary, run_audit

__all__ = ["AuditResult", "AuditSummary", "__version__", "run_audit"]
