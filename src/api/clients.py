"""
API Routes - Gestion des clients.
Principe SOLID: Interface Segregation - Routes dédiées aux clients uniquement.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import List

from ..models.schemas import ClientConfig
from ..services.stats import StatsService
from ..services.sniffer import SnifferService
from ..services.websocket import WebSocketManager


router = APIRouter(prefix="/api", tags=["clients"])


# Dépendances (seront injectées depuis main.py)
_stats_service: StatsService = None
_sniffer_service: SnifferService = None
_ws_manager: WebSocketManager = None


def init_router(stats: StatsService, sniffer: SnifferService, ws: WebSocketManager):
    """Initialise le router avec les services."""
    global _stats_service, _sniffer_service, _ws_manager
    _stats_service = stats
    _sniffer_service = sniffer
    _ws_manager = ws


def get_stats_service() -> StatsService:
    """Retourne le service de stats."""
    if _stats_service is None:
        raise HTTPException(status_code=500, detail="Service non initialisé")
    return _stats_service


def get_sniffer_service() -> SnifferService:
    """Retourne le service de sniffing."""
    if _sniffer_service is None:
        raise HTTPException(status_code=500, detail="Service non initialisé")
    return _sniffer_service


@router.post("/configure-clients")
async def configure_clients(config: ClientConfig):
    """Configure dynamiquement les clients surveillés."""
    stats = get_stats_service()
    sniffer = get_sniffer_service()
    
    cleaned_clients = [ip.strip() for ip in config.clients if ip.strip()]
    
    # Configurer les services
    stats.configure_clients(cleaned_clients)
    sniffer.set_monitored_clients(cleaned_clients)
    
    # Notifier les WebSockets
    if _ws_manager:
        await _ws_manager.broadcast({
            'type': 'clients_update',
            'clients': cleaned_clients
        })
    
    return {"success": True, "clients": cleaned_clients}


@router.get("/clients")
async def list_clients():
    """Retourne la liste des IP surveillées."""
    stats = get_stats_service()
    return {"clients": list(stats.monitored_clients)}


@router.get("/clients/ranking")
async def get_clients_ranking():
    """Retourne le classement des clients par volume de consommation et débit."""
    stats = get_stats_service()
    return stats.get_clients_ranking()


@router.get("/client/{ip}/history")
async def get_client_history(ip: str, limit: int = 60):
    """Historique des 60 dernières minutes pour un client."""
    stats = get_stats_service()
    
    if ip not in stats.monitored_clients:
        raise HTTPException(status_code=404, detail="Client non configuré")
    
    return stats.get_client_history(ip, limit)


@router.get("/client/{ip}/flows/{minute}")
async def get_client_flows(ip: str, minute: str):
    """Flux détaillés d'une minute donnée pour un client."""
    stats = get_stats_service()
    
    if ip not in stats.monitored_clients:
        raise HTTPException(status_code=404, detail="Client non configuré")
    
    result = stats.get_client_flows(ip, minute)
    if not result.get('flows'):
        raise HTTPException(status_code=404, detail="Minute non trouvée")
    
    return result


@router.get("/client/{ip}/stats")
async def get_client_stats(ip: str):
    """Statistiques agrégées d'un client."""
    stats = get_stats_service()
    
    if ip not in stats.monitored_clients:
        raise HTTPException(status_code=404, detail="Client non configuré")
    
    snapshot = stats.get_client_stats_snapshot(ip)
    history = stats.client_history.get(ip, [])
    last_record = history[-1] if history else None
    
    return {
        "client": ip,
        "stats": snapshot,
        "latest_record": last_record
    }
