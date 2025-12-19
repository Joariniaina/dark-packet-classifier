"""
WebSocketManager - Gestionnaire des connexions WebSocket.
Principe SOLID:
- Single Responsibility: Gère uniquement les WebSockets
- Interface Segregation: API simple pour broadcast
"""

from typing import List, Dict, Any
from fastapi import WebSocket


class WebSocketManager:
    """Gestionnaire des connexions WebSocket."""
    
    def __init__(self):
        """Initialise le gestionnaire."""
        self.connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket) -> None:
        """Accepte une nouvelle connexion WebSocket."""
        await websocket.accept()
        self.connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket) -> None:
        """Déconnecte un WebSocket."""
        if websocket in self.connections:
            self.connections.remove(websocket)
    
    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Envoie un message à tous les clients connectés."""
        disconnected = []
        
        for ws in self.connections:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)
        
        # Nettoyer les connexions mortes
        for ws in disconnected:
            self.disconnect(ws)
    
    async def send_to_client(self, websocket: WebSocket, message: Dict[str, Any]) -> bool:
        """Envoie un message à un client spécifique."""
        try:
            await websocket.send_json(message)
            return True
        except Exception:
            self.disconnect(websocket)
            return False
    
    @property
    def connection_count(self) -> int:
        """Retourne le nombre de connexions actives."""
        return len(self.connections)
