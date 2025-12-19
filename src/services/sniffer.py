"""
SnifferService - Service de capture de paquets.
Principe SOLID:
- Single Responsibility: Gère uniquement la capture réseau
- Open/Closed: Peut être étendu pour différentes interfaces
- Dependency Inversion: Dépend d'abstractions (ClassifierService)
"""

import threading
import time
from typing import Dict, Set, List, Callable, Optional
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP

from ..config import settings
from ..models.flow import FlowData
from .classifier import ClassifierService


class SnifferService:
    """Service de capture et traitement des paquets réseau."""
    
    def __init__(self, classifier: ClassifierService):
        """
        Initialise le service de sniffing.
        
        Args:
            classifier: Service de classification ML
        """
        self.classifier = classifier
        self.running = False
        self.interface = settings.DEFAULT_INTERFACE
        
        # Stockage des flux en cours
        self.local_flows: Dict[tuple, FlowData] = {}
        self.flow_client_map: Dict[tuple, Set[str]] = {}
        
        # Clients surveillés
        self.monitored_clients: Set[str] = set()
        
        # Queue pour les résultats
        self.result_queue: Queue = Queue()
        
        # Callbacks pour les événements
        self._on_result_callbacks: List[Callable] = []
    
    def set_monitored_clients(self, clients: List[str]) -> None:
        """Configure les clients à surveiller."""
        self.monitored_clients = set(ip.strip() for ip in clients if ip.strip())
    
    def add_result_callback(self, callback: Callable) -> None:
        """Ajoute un callback appelé à chaque résultat de classification."""
        self._on_result_callbacks.append(callback)
    
    def start(self, interface: str = None) -> bool:
        """
        Démarre le sniffer.
        
        Args:
            interface: Interface réseau à utiliser
            
        Returns:
            True si démarré avec succès
        """
        if self.running:
            return False
        
        if not self.classifier.is_loaded():
            print("❌ Modèle ML non chargé")
            return False
        
        self.interface = interface or self.interface
        self.running = True
        
        # Démarrer les threads
        threading.Thread(
            target=self._sniffer_thread, 
            args=(self.interface,), 
            daemon=True
        ).start()
        
        threading.Thread(
            target=self._cleanup_thread, 
            daemon=True
        ).start()
        
        print(f"🔍 Sniffer démarré sur {self.interface}")
        return True
    
    def stop(self) -> None:
        """Arrête le sniffer."""
        self.running = False
        print("⏹️ Sniffer arrêté")
    
    def _sniffer_thread(self, interface: str) -> None:
        """Thread de capture de paquets."""
        try:
            sniff(
                iface=interface, 
                prn=self._process_packet, 
                store=0, 
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"❌ Erreur sniffer: {e}")
    
    def _cleanup_thread(self) -> None:
        """Thread de nettoyage des flux expirés."""
        while self.running:
            self._clean_expired_flows()
            time.sleep(1)
    
    def _process_packet(self, packet) -> None:
        """Callback Scapy pour traiter chaque paquet."""
        quintuple, direction, client_ip, dest_ip = self._get_flow_quintuple(packet)
        if not quintuple:
            return
        
        # Vérifier si le paquet concerne un client surveillé
        monitored_flow_clients = []
        if self.monitored_clients:
            monitored_flow_clients = self._detect_monitored_clients(packet)
            if not monitored_flow_clients:
                return
        
        flow_key = quintuple
        current_time = packet.time
        
        # Créer ou récupérer le flux
        if flow_key not in self.local_flows:
            self.local_flows[flow_key] = FlowData(start_time=current_time)
        
        if flow_key not in self.flow_client_map:
            self.flow_client_map[flow_key] = set(monitored_flow_clients)
        else:
            self.flow_client_map[flow_key].update(monitored_flow_clients)
        
        flow = self.local_flows[flow_key]
        flow.update_flow(packet, direction, current_time=current_time)
        
        # Classification sur fin de connexion TCP
        if flow_key[4] == 6 and TCP in packet:
            if packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04:  # FIN ou RST
                self._classify_and_emit(flow, flow_key, client_ip, dest_ip)
                return
        
        # Classification après seuil de paquets
        if flow.total_packets >= settings.CLASSIFY_PACKET_THRESHOLD:
            self._classify_and_emit(flow, flow_key, client_ip, dest_ip)
    
    def _classify_and_emit(self, flow: FlowData, flow_key: tuple, 
                          client_ip: str, dest_ip: str) -> None:
        """Classifie un flux et émet le résultat."""
        clients_list = list(self.flow_client_map.get(flow_key, []))
        
        result = self.classifier.classify_flow(
            flow, flow_key, client_ip, dest_ip, clients_list
        )
        
        # Mettre dans la queue
        self.result_queue.put(result)
        
        # Appeler les callbacks
        for callback in self._on_result_callbacks:
            try:
                callback(result)
            except Exception as e:
                print(f"Erreur callback: {e}")
        
        # Nettoyer le flux
        del self.local_flows[flow_key]
        self.flow_client_map.pop(flow_key, None)
    
    def _clean_expired_flows(self) -> None:
        """Nettoie et classifie les flux expirés."""
        current_time = time.time()
        flows_to_classify = []
        
        for key, flow in list(self.local_flows.items()):
            if current_time - flow.last_time > settings.TIMEOUT_FLOW:
                flows_to_classify.append((key, flow))
        
        for key, flow in flows_to_classify:
            if key in self.local_flows:
                client_ip = key[0]
                dest_ip = key[2]
                self._classify_and_emit(flow, key, client_ip, dest_ip)
    
    @staticmethod
    def _get_flow_quintuple(packet) -> tuple:
        """Extrait la quintuple pour identifier un flux."""
        if IP not in packet:
            return None, None, None, None
        
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        if TCP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
        elif UDP in packet:
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        else:
            return None, None, None, None
        
        if (ip_src, port_src) < (ip_dst, port_dst):
            quintuple = (ip_src, port_src, ip_dst, port_dst, protocol)
            direction = 'forward'
            client_ip = ip_src
            dest_ip = ip_dst
        else:
            quintuple = (ip_dst, port_dst, ip_src, port_src, protocol)
            direction = 'reverse'
            client_ip = ip_dst
            dest_ip = ip_src
        
        return quintuple, direction, client_ip, dest_ip
    
    def _detect_monitored_clients(self, packet) -> List[str]:
        """Retourne la liste des IP surveillées impliquées dans le paquet."""
        clients = []
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if ip_src in self.monitored_clients:
                clients.append(ip_src)
            if ip_dst in self.monitored_clients and ip_dst not in clients:
                clients.append(ip_dst)
        return clients
    
    @property
    def status(self) -> dict:
        """Retourne le statut du sniffer."""
        return {
            'running': self.running,
            'interface': self.interface,
            'model_loaded': self.classifier.is_loaded(),
            'monitored_clients': list(self.monitored_clients),
            'active_flows': len(self.local_flows)
        }
