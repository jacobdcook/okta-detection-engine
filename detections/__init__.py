from .mfa_fatigue import detect_mfa_fatigue
from .impossible_travel import detect_impossible_travel
from .brute_force import detect_brute_force
from .suspicious_mfa import detect_suspicious_mfa
from .admin_escalation import detect_admin_escalation

ALL_DETECTIONS = [
    detect_mfa_fatigue,
    detect_impossible_travel,
    detect_brute_force,
    detect_suspicious_mfa,
    detect_admin_escalation,
]
