"""
Stats Models - Structures de données pour les statistiques.
Principe SOLID: Single Responsibility - Modèles de données uniquement.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict


@dataclass
class MinuteBuffer:
    """Buffer pour agréger les données de la minute courante."""
    
    start_time: Optional[datetime] = None
    flows: List[dict] = field(default_factory=list)
    apps_count: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    apps_confidence: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    destinations: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_volume: int = 0
    malware_detected: bool = False
    
    def add_flow(self, flow_result: dict) -> None:
        """Ajoute un flux au buffer."""
        clean_label = flow_result.get('label', 'UNKNOWN').replace(' (?)', '')
        
        self.flows.append(flow_result)
        self.apps_count[clean_label] += 1
        self.apps_confidence[clean_label].append(flow_result.get('confidence', 0))
        self.destinations[flow_result.get('dest_ip', 'N/A')] += 1
        self.total_volume += flow_result.get('volume', 0)
        
        if flow_result.get('is_malware', False):
            self.malware_detected = True
    
    def reset(self) -> None:
        """Réinitialise le buffer pour la prochaine minute."""
        self.start_time = None
        self.flows = []
        self.apps_count = defaultdict(int)
        self.apps_confidence = defaultdict(list)
        self.destinations = defaultdict(int)
        self.total_volume = 0
        self.malware_detected = False
    
    def is_empty(self) -> bool:
        """Vérifie si le buffer est vide."""
        return len(self.apps_count) == 0


@dataclass
class MinuteRecord:
    """Enregistrement d'une minute d'activité."""
    
    time: str
    app: str
    confidence: float
    dest_ip: str
    total_flows: int
    volume: int
    is_malware: bool
    all_apps: Dict[str, int]
    top_destinations: List[dict]
    flows_detail: List[dict]
    volume_kb: float = 0.0
    flows_count: int = 0
    
    def __post_init__(self):
        self.volume_kb = round(self.volume / 1024, 2)
        self.flows_count = self.total_flows
    
    @classmethod
    def from_buffer(cls, buffer: MinuteBuffer, timestamp: str) -> 'MinuteRecord':
        """Crée un enregistrement à partir d'un buffer."""
        flows = buffer.flows
        total_flows = len(flows)
        
        # Déterminer l'app dominante
        if buffer.apps_count:
            dominant_app = max(buffer.apps_count.items(), key=lambda x: x[1])[0]
            confidences = buffer.apps_confidence.get(dominant_app, [0])
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        else:
            dominant_app = "UNKNOWN"
            avg_confidence = 0
        
        # Top destinations
        top_dest = sorted(buffer.destinations.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Détails des flux
        flows_detail = [
            {
                'label': f.get('label', 'UNKNOWN').replace(' (?)', ''),
                'confidence': round(f.get('confidence', 0), 1),
                'src_ip': f.get('client_ip', 'Local'),
                'dest_ip': f.get('dest_ip', 'N/A'),
                'dest_port': f.get('dest_port', 0),
                'volume': f.get('volume', 0),
                'protocol': f.get('protocol', 'TCP'),
                'packets': f.get('packets', 1),
                'timestamp': f.get('timestamp')
            }
            for f in flows
        ]
        
        return cls(
            time=timestamp,
            app=dominant_app,
            confidence=round(avg_confidence, 1),
            dest_ip=top_dest[0][0] if top_dest else "N/A",
            total_flows=total_flows,
            volume=buffer.total_volume,
            is_malware=buffer.malware_detected,
            all_apps=dict(buffer.apps_count),
            top_destinations=[{'ip': ip, 'hits': hits} for ip, hits in top_dest],
            flows_detail=flows_detail
        )
    
    def to_dict(self) -> dict:
        """Convertit l'enregistrement en dictionnaire."""
        return {
            'time': self.time,
            'app': self.app,
            'confidence': self.confidence,
            'dest_ip': self.dest_ip,
            'total_flows': self.total_flows,
            'flows_count': self.flows_count,
            'volume': self.volume,
            'volume_kb': self.volume_kb,
            'is_malware': self.is_malware,
            'all_apps': self.all_apps,
            'top_destinations': self.top_destinations,
            'flows_detail': self.flows_detail
        }


@dataclass
class ClientStats:
    """Statistiques à long terme pour un client."""
    
    total_flows: int = 0
    total_volume_bytes: int = 0
    malware_alerts: int = 0
    app_distribution: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    protocols: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    destinations: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    confidence_sum: float = 0.0
    confidence_count: int = 0
    timeline: List[dict] = field(default_factory=list)
    last_update: Optional[datetime] = None
    session_start: Optional[float] = None
    session_duration_seconds: float = 0
    bandwidth_bytes_per_second: float = 0
    bandwidth_mbps: float = 0.0
    
    def update_from_flow(self, flow_result: dict) -> None:
        """Met à jour les statistiques avec un nouveau flux."""
        import time
        
        clean_label = flow_result.get('label', 'UNKNOWN').replace(' (?)', '')
        
        self.total_flows += 1
        self.total_volume_bytes += flow_result.get('volume', 0)
        
        if flow_result.get('is_malware', False):
            self.malware_alerts += 1
        
        self.app_distribution[clean_label] += 1
        self.protocols[flow_result.get('protocol', 'TCP')] += 1
        self.destinations[flow_result.get('dest_ip', 'N/A')] += 1
        self.confidence_sum += flow_result.get('confidence', 0)
        self.confidence_count += 1
        self.last_update = datetime.now()
        
        # Calcul du débit
        if self.session_start is None:
            self.session_start = time.time()
        
        session_duration = time.time() - self.session_start
        self.session_duration_seconds = session_duration
        
        if session_duration > 0:
            bytes_per_second = self.total_volume_bytes / session_duration
            self.bandwidth_bytes_per_second = bytes_per_second
            self.bandwidth_mbps = round((bytes_per_second * 8) / 1_000_000, 3)
    
    @property
    def average_confidence(self) -> float:
        """Retourne la confiance moyenne."""
        if self.confidence_count == 0:
            return 0.0
        return self.confidence_sum / self.confidence_count
    
    def get_top_apps(self, limit: int = 5) -> List[dict]:
        """Retourne les top applications."""
        sorted_apps = sorted(self.app_distribution.items(), key=lambda x: x[1], reverse=True)
        return [{'label': label, 'count': count} for label, count in sorted_apps[:limit]]
    
    def get_top_destinations(self, limit: int = 5) -> List[dict]:
        """Retourne les top destinations."""
        sorted_dest = sorted(self.destinations.items(), key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'hits': hits} for ip, hits in sorted_dest[:limit]]
    
    def to_snapshot(self) -> dict:
        """Crée un snapshot des statistiques pour API/WebSocket."""
        return {
            'total_flows': self.total_flows,
            'malware_alerts': self.malware_alerts,
            'volume_mb': round(self.total_volume_bytes / (1024 * 1024), 2),
            'average_confidence': round(self.average_confidence, 1),
            'top_apps': self.get_top_apps(),
            'top_destinations': self.get_top_destinations(),
            'last_update': self.last_update.strftime("%H:%M:%S") if self.last_update else None,
            'timeline': self.timeline[-20:],
            'bandwidth_mbps': self.bandwidth_mbps,
            'session_duration_seconds': self.session_duration_seconds
        }
