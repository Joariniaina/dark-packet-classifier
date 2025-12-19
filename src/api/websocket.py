"""
WebSocket Route.
Principe SOLID: Interface Segregation - Route WebSocket séparée.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..services.websocket import WebSocketManager
from ..services.stats import StatsService
from ..services.sniffer import SnifferService


router = APIRouter(tags=["websocket"])


# Dépendances (seront injectées depuis main.py)
_ws_manager: WebSocketManager = None
_stats_service: StatsService = None
_sniffer_service: SnifferService = None


def init_router(ws: WebSocketManager, stats: StatsService, sniffer: SnifferService):
    """Initialise le router avec les services."""
    global _ws_manager, _stats_service, _sniffer_service
    _ws_manager = ws
    _stats_service = stats
    _sniffer_service = sniffer


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket pour les mises à jour en temps réel."""
    await _ws_manager.connect(websocket)
    
    try:
        # Envoyer l'état initial
        init_data = _stats_service.get_init_data()
        init_data['running'] = _sniffer_service.running
        
        await _ws_manager.send_to_client(websocket, {
            'type': 'init',
            'data': init_data
        })
        
        # Boucle de maintien de connexion
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
                
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)
