"""
StatsService - Service de gestion des statistiques.
Principe SOLID:
- Single Responsibility: Gère uniquement les statistiques
- Open/Closed: Extensible pour nouvelles métriques
- Liskov: Peut être substitué par d'autres implémentations
"""

from datetime import datetime
from typing import Dict, List, Optional, Set
from collections import defaultdict

from ..config import settings
from ..models.stats import MinuteBuffer, MinuteRecord, ClientStats


def format_duration(seconds: float) -> str:
    """Formate une durée en secondes en format lisible."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {mins}m {secs}s"


class StatsService:
    """Service de gestion des statistiques de trafic."""
    
    def __init__(self):
        """Initialise le service de statistiques."""
        # Statistiques globales
        self.global_stats = {
            'total_flows': 0,
            'malware_alerts': 0,
            'total_volume_bytes': 0,
            'volume_by_type': defaultdict(int),
            'volume_by_ip': defaultdict(int),
            'flows_by_ip': defaultdict(int),
            'flows_by_type': defaultdict(int),
            'malware_by_ip': defaultdict(int),
            'usage_by_dest': defaultdict(float),
            'minute_history': [],
            'timeline': []
        }
        
        # Buffer de la minute courante
        self.current_minute_buffer = MinuteBuffer()
        
        # Données par client
        self.monitored_clients: Set[str] = set()
        self.client_buffers: Dict[str, MinuteBuffer] = defaultdict(MinuteBuffer)
        self.client_stats: Dict[str, ClientStats] = defaultdict(ClientStats)
        self.client_history: Dict[str, List[dict]] = defaultdict(list)
    
    def configure_clients(self, clients: List[str]) -> None:
        """Configure les clients à surveiller."""
        cleaned_clients = set(ip.strip() for ip in clients if ip.strip())
        
        # Nettoyer les anciens clients
        for ip in list(self.client_history.keys()):
            if ip not in cleaned_clients:
                self.client_history.pop(ip, None)
        for ip in list(self.client_stats.keys()):
            if ip not in cleaned_clients:
                self.client_stats.pop(ip, None)
        for ip in list(self.client_buffers.keys()):
            if ip not in cleaned_clients:
                self.client_buffers.pop(ip, None)
        
        # Initialiser les nouveaux clients
        for ip in cleaned_clients:
            if ip not in self.client_history:
                self.client_history[ip] = []
            if ip not in self.client_stats:
                self.client_stats[ip] = ClientStats()
            if ip not in self.client_buffers:
                self.client_buffers[ip] = MinuteBuffer()
        
        self.monitored_clients = cleaned_clients
    
    def process_result(self, result: dict) -> None:
        """Traite un résultat de classification."""
        # Initialiser le buffer si nécessaire
        if self.current_minute_buffer.start_time is None:
            self.current_minute_buffer.start_time = datetime.now()
        
        clean_label = result['label'].replace(' (?)', '')
        
        # Mise à jour des statistiques globales
        self.global_stats['total_flows'] += 1
        self.global_stats['total_volume_bytes'] += result['volume']
        self.global_stats['volume_by_type'][clean_label] += result['volume']
        self.global_stats['volume_by_ip'][result['client_ip']] += result['volume']
        self.global_stats['flows_by_ip'][result['client_ip']] += 1
        self.global_stats['flows_by_type'][clean_label] += 1
        self.global_stats['usage_by_dest'][result['dest_ip']] += result['duration']
        
        if result['is_malware']:
            self.global_stats['malware_alerts'] += 1
            self.global_stats['malware_by_ip'][result['client_ip']] += 1
        
        # Ajouter au buffer global
        self.current_minute_buffer.add_flow(result)
        
        # Mise à jour par client
        for client_ip in result.get('monitored_clients', []):
            self._process_client_result(client_ip, result)
    
    def _process_client_result(self, client_ip: str, result: dict) -> None:
        """Traite un résultat pour un client spécifique."""
        # Buffer client
        buffer = self.client_buffers[client_ip]
        if buffer.start_time is None:
            buffer.start_time = datetime.now()
        buffer.add_flow(result)
        
        # Stats client
        stats = self.client_stats[client_ip]
        stats.update_from_flow(result)
    
    def finalize_minute(self) -> Optional[dict]:
        """Finalise la minute courante et retourne l'enregistrement."""
        timestamp = datetime.now().strftime("%H:%M")
        minute_data = None
        
        # Traiter le buffer global
        if not self.current_minute_buffer.is_empty():
            record = MinuteRecord.from_buffer(self.current_minute_buffer, timestamp)
            record_dict = record.to_dict()
            
            self.global_stats['minute_history'].append(record_dict)
            if len(self.global_stats['minute_history']) > settings.MAX_HISTORY_ENTRIES:
                self.global_stats['minute_history'] = self.global_stats['minute_history'][-settings.MAX_HISTORY_ENTRIES:]
            
            # Timeline snapshot
            snapshot = {
                'time': timestamp,
                'total_flows': self.global_stats['total_flows'],
                'volume_mb': round(self.global_stats['total_volume_bytes'] / (1024*1024), 2),
                'malware_alerts': self.global_stats['malware_alerts'],
                'minute_flows': record.total_flows
            }
            self.global_stats['timeline'].append(snapshot)
            if len(self.global_stats['timeline']) > settings.MAX_HISTORY_ENTRIES:
                self.global_stats['timeline'] = self.global_stats['timeline'][-settings.MAX_HISTORY_ENTRIES:]
            
            minute_data = {
                'record': record_dict,
                'stats': self.get_global_stats_summary(),
                'apps_distribution': dict(self.global_stats['flows_by_type'])
            }
            
            print(f"📊 {timestamp} - App dominante: {record.app} ({record.confidence:.1f}%)")
        
        # Réinitialiser le buffer global
        self.current_minute_buffer.reset()
        
        return minute_data
    
    def finalize_client_minutes(self) -> Dict[str, dict]:
        """Finalise les minutes de tous les clients."""
        timestamp = datetime.now().strftime("%H:%M")
        client_data = {}
        
        for client_ip in list(self.monitored_clients):
            buffer = self.client_buffers[client_ip]
            
            if not buffer.is_empty():
                record = MinuteRecord.from_buffer(buffer, timestamp)
                record_dict = record.to_dict()
                
                self.client_history[client_ip].append(record_dict)
                if len(self.client_history[client_ip]) > settings.MAX_HISTORY_ENTRIES:
                    self.client_history[client_ip] = self.client_history[client_ip][-settings.MAX_HISTORY_ENTRIES:]
                
                # Timeline client
                stats = self.client_stats[client_ip]
                stats.timeline.append({
                    'time': timestamp,
                    'flows': record.total_flows,
                    'volume_kb': record.volume_kb,
                    'app': record.app,
                    'confidence': record.confidence
                })
                if len(stats.timeline) > 120:
                    stats.timeline = stats.timeline[-120:]
                
                client_data[client_ip] = {
                    'record': record_dict,
                    'stats': stats.to_snapshot()
                }
            
            # Réinitialiser le buffer client
            self.client_buffers[client_ip] = MinuteBuffer()
        
        return client_data
    
    def get_global_stats_summary(self) -> dict:
        """Retourne un résumé des statistiques globales."""
        return {
            'total_flows': self.global_stats['total_flows'],
            'malware_alerts': self.global_stats['malware_alerts'],
            'total_volume_mb': round(self.global_stats['total_volume_bytes'] / (1024*1024), 2)
        }
    
    def get_full_stats(self) -> dict:
        """Retourne les statistiques complètes."""
        return {
            'total_flows': self.global_stats['total_flows'],
            'malware_alerts': self.global_stats['malware_alerts'],
            'total_volume_mb': round(self.global_stats['total_volume_bytes'] / (1024*1024), 2),
            'flows_by_type': dict(self.global_stats['flows_by_type']),
            'volume_by_type_mb': {
                k: round(v/(1024*1024), 2) 
                for k, v in self.global_stats['volume_by_type'].items()
            },
            'top_destinations': dict(
                sorted(self.global_stats['usage_by_dest'].items(), 
                      key=lambda x: x[1], reverse=True)[:10]
            ),
            'timeline': self.global_stats['timeline'][-20:]
        }
    
    def get_history(self, limit: int = 60) -> dict:
        """Retourne l'historique global."""
        history_light = []
        for record in self.global_stats['minute_history'][-limit:]:
            history_light.append({
                'time': record['time'],
                'app': record['app'],
                'confidence': record['confidence'],
                'dest_ip': record['dest_ip'],
                'total_flows': record['total_flows'],
                'volume': record['volume'],
                'is_malware': record['is_malware'],
                'all_apps': record.get('all_apps', {})
            })
        return {
            'history': history_light,
            'total': len(self.global_stats['minute_history'])
        }
    
    def get_minute_details(self, time_key: str) -> dict:
        """Retourne les détails d'une minute spécifique."""
        for record in self.global_stats['minute_history']:
            if record['time'] == time_key:
                flows = record.get('flows_detail', [])
                confidences = [f.get('confidence', 0) for f in flows]
                avg_confidence = round(sum(confidences) / len(confidences), 1) if confidences else 0
                
                enriched_flows = []
                for flow in flows:
                    enriched_flows.append({
                        'src_ip': flow.get('src_ip', 'Local'),
                        'dest_ip': flow.get('dest_ip', 'N/A'),
                        'dest_port': flow.get('dest_port', 0),
                        'protocol': flow.get('protocol', 'TCP'),
                        'app': flow.get('label', 'UNKNOWN'),
                        'confidence': flow.get('confidence', 0),
                        'bytes': flow.get('volume', 0),
                        'packets': flow.get('packets', 1)
                    })
                
                return {
                    'success': True,
                    'time': time_key,
                    'dominant_app': record['app'],
                    'total_flows': record['total_flows'],
                    'average_confidence': avg_confidence,
                    'all_apps': record.get('all_apps', {}),
                    'flows': enriched_flows
                }
        
        return {'success': False, 'error': 'Minute non trouvée'}
    
    def get_client_history(self, ip: str, limit: int = 60) -> dict:
        """Retourne l'historique d'un client."""
        history = self.client_history.get(ip, [])
        return {
            'client': ip,
            'history': history[-limit:]
        }
    
    def get_client_stats_snapshot(self, ip: str) -> dict:
        """Retourne les statistiques d'un client."""
        stats = self.client_stats.get(ip)
        if stats:
            return stats.to_snapshot()
        return ClientStats().to_snapshot()
    
    def get_client_flows(self, ip: str, minute: str) -> dict:
        """Retourne les flux d'un client pour une minute donnée."""
        for record in self.client_history.get(ip, []):
            if record['time'] == minute:
                return {
                    'client': ip,
                    'time': minute,
                    'flows': record.get('flows_detail', [])
                }
        return {'client': ip, 'time': minute, 'flows': []}
    
    def get_clients_ranking(self) -> dict:
        """Retourne le classement des clients par volume."""
        ranking = []
        
        for ip in self.monitored_clients:
            stats = self.client_stats.get(ip, ClientStats())
            volume_bytes = stats.total_volume_bytes
            bandwidth_mbps = stats.bandwidth_mbps
            session_duration = stats.session_duration_seconds
            
            ranking.append({
                'ip': ip,
                'volume_bytes': volume_bytes,
                'volume_mb': round(volume_bytes / (1024 * 1024), 2),
                'volume_gb': round(volume_bytes / (1024 * 1024 * 1024), 3),
                'total_flows': stats.total_flows,
                'malware_alerts': stats.malware_alerts,
                'bandwidth_mbps': round(bandwidth_mbps, 3),
                'bandwidth_kbps': round(bandwidth_mbps * 1000, 1),
                'session_duration_seconds': round(session_duration, 1),
                'session_duration_formatted': format_duration(session_duration)
            })
        
        # Trier par volume décroissant
        ranking.sort(key=lambda x: x['volume_bytes'], reverse=True)
        
        # Calculer les totaux
        total_volume = sum(c['volume_bytes'] for c in ranking)
        total_bandwidth = sum(c['bandwidth_mbps'] for c in ranking)
        
        # Ajouter rang et pourcentage
        for i, client in enumerate(ranking):
            client['rank'] = i + 1
            client['percentage'] = round(
                (client['volume_bytes'] / total_volume * 100), 1
            ) if total_volume > 0 else 0
            client['bandwidth_percentage'] = round(
                (client['bandwidth_mbps'] / total_bandwidth * 100), 1
            ) if total_bandwidth > 0 else 0
        
        return {
            'ranking': ranking,
            'total_bandwidth_mbps': round(total_bandwidth, 3),
            'total_volume_mb': round(total_volume / (1024 * 1024), 2),
            'total_clients': len(ranking)
        }
    
    def get_apps_list(self) -> List[dict]:
        """Retourne la liste des applications détectées."""
        apps = []
        for label, count in sorted(
            self.global_stats['flows_by_type'].items(), 
            key=lambda x: x[1], 
            reverse=True
        ):
            volume_mb = round(
                self.global_stats['volume_by_type'].get(label, 0) / (1024*1024), 2
            )
            apps.append({
                'name': label,
                'flows': count,
                'volume_mb': volume_mb,
                'is_malware': settings.is_malware(label),
                'category': settings.get_app_category(label)
            })
        return apps
    
    def get_init_data(self) -> dict:
        """Retourne les données d'initialisation pour WebSocket."""
        return {
            'running': False,  # Sera mis à jour par l'appelant
            'history': self.global_stats['minute_history'][-30:],
            'apps_distribution': dict(self.global_stats['flows_by_type']),
            'clients': list(self.monitored_clients),
            'client_history': {
                ip: self.client_history[ip][-30:] 
                for ip in self.monitored_clients
            },
            'client_stats': {
                ip: self.get_client_stats_snapshot(ip) 
                for ip in self.monitored_clients
            },
            'stats': self.get_global_stats_summary()
        }
