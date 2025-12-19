"""
API Routes - Contrôle du sniffer.
Principe SOLID: Interface Segregation - Routes dédiées au sniffer uniquement.
"""

from fastapi import APIRouter, Form, HTTPException

from ..config import settings
from ..services.sniffer import SnifferService


router = APIRouter(prefix="/api", tags=["sniffer"])


# Dépendance (sera injectée depuis main.py)
_sniffer_service: SnifferService = None


def init_router(sniffer: SnifferService):
    """Initialise le router avec le service."""
    global _sniffer_service
    _sniffer_service = sniffer


def get_sniffer_service() -> SnifferService:
    """Retourne le service de sniffing."""
    if _sniffer_service is None:
        raise HTTPException(status_code=500, detail="Service non initialisé")
    return _sniffer_service


@router.post("/start")
async def start_sniffer(interface: str = Form(default=settings.DEFAULT_INTERFACE)):
    """Démarre le sniffer sur l'interface spécifiée."""
    sniffer = get_sniffer_service()
    
    if not sniffer.classifier.is_loaded():
        return {"success": False, "error": "Modèle ML non chargé"}
    
    if sniffer.running:
        return {"success": False, "error": "Sniffer déjà en cours"}
    
    success = sniffer.start(interface)
    
    if success:
        return {"success": True, "message": f"Sniffer démarré sur {interface}"}
    else:
        return {"success": False, "error": "Échec du démarrage"}


@router.post("/stop")
async def stop_sniffer():
    """Arrête le sniffer."""
    sniffer = get_sniffer_service()
    sniffer.stop()
    return {"success": True, "message": "Sniffer arrêté"}


@router.get("/status")
async def get_status():
    """Retourne le statut du sniffer."""
    sniffer = get_sniffer_service()
    return sniffer.status
