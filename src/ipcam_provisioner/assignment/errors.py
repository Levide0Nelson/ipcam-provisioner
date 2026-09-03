"""Erreurs du module d'attribution (partagées entre base et attribueurs)."""


class AssignmentError(RuntimeError):
    """Échec définitif de l'attribution d'une caméra (HTTP ou protocole)."""


__all__ = ["AssignmentError"]
