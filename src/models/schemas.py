"""
Schémas Pydantic pour l'API.
Principe SOLID: Single Responsibility - Validation des données uniquement.
"""

from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime


class ClientConfig(BaseModel):
    """Configuration des clients à surveiller."""
    clients: List[str]


class FlowResult(BaseModel):
    """Résultat de classification d'un flux."""
    timestamp: str
    label: str
    confidence: float
    confidence_level: str
    all_probabilities: Dict[str, float]
    volume: int
    client_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    duration: float
    packets: int
    is_malware: bool
    monitored_clients: List[str] = []
    
    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    """Réponse des statistiques globales."""
    total_flows: int
    malware_alerts: int
    total_volume_mb: float
    flows_by_type: Dict[str, int]
    volume_by_type_mb: Dict[str, float]
    top_destinations: Dict[str, float]
    timeline: List[dict]


class ClientRankingItem(BaseModel):
    """Item du classement des clients."""
    ip: str
    volume_bytes: int
    volume_mb: float
    volume_gb: float
    total_flows: int
    malware_alerts: int
    bandwidth_mbps: float
    bandwidth_kbps: float
    session_duration_seconds: float
    session_duration_formatted: str
    rank: int = 0
    percentage: float = 0.0
    bandwidth_percentage: float = 0.0


class ClientRankingResponse(BaseModel):
    """Réponse du classement des clients."""
    ranking: List[ClientRankingItem]
    total_bandwidth_mbps: float
    total_volume_mb: float
    total_clients: int


class HistoryRecord(BaseModel):
    """Enregistrement d'historique simplifié."""
    time: str
    app: str
    confidence: float
    dest_ip: str
    total_flows: int
    volume: int
    is_malware: bool
    all_apps: Dict[str, int] = {}


class MinuteDetailsResponse(BaseModel):
    """Détails d'une minute spécifique."""
    success: bool
    time: Optional[str] = None
    dominant_app: Optional[str] = None
    total_flows: Optional[int] = None
    average_confidence: Optional[float] = None
    all_apps: Dict[str, int] = {}
    flows: List[dict] = []
    error: Optional[str] = None


class SnifferStatusResponse(BaseModel):
    """Statut du sniffer."""
    running: bool
    interface: str
    is_model_loaded: bool
    
    model_config = {"protected_namespaces": ()}


class StartSnifferResponse(BaseModel):
    """Réponse au démarrage du sniffer."""
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
