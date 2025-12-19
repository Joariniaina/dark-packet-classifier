"""
API Routes - Statistiques et historique.
Principe SOLID: Interface Segregation - Routes dédiées aux stats uniquement.
"""

from fastapi import APIRouter, HTTPException
from typing import List

from ..services.stats import StatsService


router = APIRouter(prefix="/api", tags=["stats"])


# Dépendance (sera injectée depuis main.py)
_stats_service: StatsService = None


def init_router(stats: StatsService):
    """Initialise le router avec le service."""
    global _stats_service
    _stats_service = stats


def get_stats_service() -> StatsService:
    """Retourne le service de stats."""
    if _stats_service is None:
        raise HTTPException(status_code=500, detail="Service non initialisé")
    return _stats_service


@router.get("/stats")
async def get_stats():
    """Retourne les statistiques globales."""
    stats = get_stats_service()
    return stats.get_full_stats()


@router.get("/history")
async def get_history(limit: int = 60):
    """Retourne l'historique par minute (1 entrée = 1 minute)."""
    stats = get_stats_service()
    return stats.get_history(limit)


@router.get("/history/{time_key}/flows")
async def get_minute_flows(time_key: str):
    """Retourne les flux détaillés d'une minute spécifique."""
    stats = get_stats_service()
    
    for record in stats.global_stats['minute_history']:
        if record['time'] == time_key:
            return {
                "time": record['time'],
                "app": record['app'],
                "total_flows": record['total_flows'],
                "flows": record.get('flows_detail', [])
            }
    
    return {"error": "Minute non trouvée", "flows": []}


@router.get("/minute-details/{time}")
async def get_minute_details(time: str):
    """Retourne les détails complets d'une minute spécifique pour le modal."""
    stats = get_stats_service()
    return stats.get_minute_details(time)


@router.get("/apps")
async def get_apps():
    """Retourne les applications détectées par type de trafic."""
    stats = get_stats_service()
    return stats.get_apps_list()
