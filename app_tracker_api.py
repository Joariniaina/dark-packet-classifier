"""
Application Tracker Dashboard - FastAPI avec Classification IA
Utilise le modèle ML pour classifier le trafic réseau et identifier les applications
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import asyncio
import threading
import time
import math
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set
from queue import Queue
import json

# Librairies ML et réseau
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP

# ============================================================================
# CONFIGURATION
# ============================================================================

MODEL_FILENAME = 'traffic_classifier_model.joblib'
ENCODER_FILENAME = 'traffic_label_encoder.joblib'
TIMEOUT_FLOW = 10
CLASSIFY_PACKET_THRESHOLD = 10
HISTORY_UPDATE_INTERVAL = 60  # Mise à jour de l'historique toutes les 60 secondes
DEFAULT_INTERFACE = "wlp3s0"  # Interface WiFi par défaut
MIN_CONFIDENCE_THRESHOLD = 0.3  # Seuil minimum de confiance pour une prédiction fiable

FEATURE_COLUMNS = [
    'duration', 'total_fiat', 'total_biat', 'min_fiat', 'min_biat', 
    'max_fiat', 'max_biat', 'mean_fiat', 'mean_biat', 'flowPktsPerSecond', 
    'flowBytesPerSecond', 'min_flowiat', 'max_flowiat', 'mean_flowiat', 
    'std_flowiat', 'min_active', 'mean_active', 'max_active', 'std_active', 
    'min_idle', 'mean_idle', 'max_idle', 'std_idle' 
]

# ============================================================================
# VARIABLES GLOBALES
# ============================================================================

local_flows: Dict = {}
model = None
label_encoder = None
result_queue = Queue()
connected_websockets: List[WebSocket] = []
sniffer_running = False
network_interface = DEFAULT_INTERFACE
MONITORED_CLIENTS: Set[str] = set()
flow_client_map: Dict = {}


def format_duration(seconds: float) -> str:
    """Formate une durée en secondes en format lisible (ex: 2h 15m 30s)."""
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


def create_minute_buffer():
    """Factory helper for per-minute aggregation buffers."""
    return {
        'start_time': None,
        'flows': [],
        'apps_count': defaultdict(int),
        'apps_confidence': defaultdict(list),
        'destinations': defaultdict(int),
        'total_volume': 0,
        'malware_detected': False
    }


def create_client_stats():
    """Factory helper for per-client long term statistics."""
    return {
        'total_flows': 0,
        'total_volume_bytes': 0,
        'malware_alerts': 0,
        'app_distribution': defaultdict(int),
        'protocols': defaultdict(int),
        'destinations': defaultdict(int),
        'confidence_sum': 0.0,
        'confidence_count': 0,
        'timeline': [],
        'last_update': None,
        'session_start': None,  # Timestamp de début de session
        'session_duration_seconds': 0,  # Durée totale de la session
        'bandwidth_bytes_per_second': 0,  # Débit moyen en bytes/s
        'bandwidth_mbps': 0.0  # Débit en Megabits par seconde
    }


def build_minute_record_from_buffer(buffer: dict, timestamp: str) -> dict:
    """Crée un enregistrement de minute à partir d'un buffer aggregé."""
    flows = buffer['flows']
    total_flows = len(flows)
    if buffer['apps_count']:
        dominant_app = max(buffer['apps_count'].items(), key=lambda x: x[1])[0]
        confidences = buffer['apps_confidence'].get(dominant_app, [0])
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    else:
        dominant_app = "UNKNOWN"
        avg_confidence = 0

    top_dest = sorted(buffer['destinations'].items(), key=lambda x: x[1], reverse=True)[:5]

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

    return {
        'time': timestamp,
        'app': dominant_app,
        'confidence': round(avg_confidence, 1),
        'dest_ip': top_dest[0][0] if top_dest else "N/A",
        'total_flows': total_flows,
        'flows_count': total_flows,
        'volume': buffer['total_volume'],
        'volume_kb': round(buffer['total_volume'] / 1024, 2),
        'is_malware': buffer['malware_detected'],
        'all_apps': dict(buffer['apps_count']),
        'top_destinations': [
            {'ip': ip, 'hits': hits} for ip, hits in top_dest
        ],
        'flows_detail': flows_detail
    }


def build_client_stats_snapshot(client_ip: str) -> dict:
    """Construit les statistiques courtes d'un client pour API/WebSocket."""
    stats = per_client_stats[client_ip]
    avg_confidence = stats['confidence_sum'] / stats['confidence_count'] if stats['confidence_count'] else 0
    top_apps = sorted(stats['app_distribution'].items(), key=lambda x: x[1], reverse=True)[:5]
    top_dest = sorted(stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        'total_flows': stats['total_flows'],
        'malware_alerts': stats['malware_alerts'],
        'volume_mb': round(stats['total_volume_bytes'] / (1024 * 1024), 2),
        'average_confidence': round(avg_confidence, 1),
        'top_apps': [{'label': label, 'count': count} for label, count in top_apps],
        'top_destinations': [{'ip': ip, 'hits': hits} for ip, hits in top_dest],
        'last_update': stats['last_update'].strftime("%H:%M:%S") if stats['last_update'] else None,
        'timeline': stats['timeline'][-20:]
    }

# Statistiques et historique
stats_data = {
    'total_flows': 0,
    'malware_alerts': 0,
    'total_volume_bytes': 0,
    'volume_by_type': defaultdict(int),
    'volume_by_ip': defaultdict(int),
    'flows_by_ip': defaultdict(int),
    'flows_by_type': defaultdict(int),
    'malware_by_ip': defaultdict(int),
    'usage_by_dest': defaultdict(float),
    'minute_history': [],  # Historique par minute (1 entrée = 1 minute)
    'timeline': []  # Données temporelles pour graphiques
}

# Buffer pour agréger les données de la minute courante
current_minute_buffer = {
    'start_time': None,
    'flows': [],  # Liste des flux détectés cette minute
    'apps_count': defaultdict(int),  # Compteur par application
    'apps_confidence': defaultdict(list),  # Confiances par application
    'destinations': defaultdict(int),  # IPs de destination
    'total_volume': 0,
    'malware_detected': False
}

# Multi-client data stores
per_client_history = defaultdict(list)
client_buffers = defaultdict(create_minute_buffer)
per_client_stats = defaultdict(create_client_stats)

# ============================================================================
# CLASSE FLOWDATA - Extraction des features
# ============================================================================

class FlowData:
    """Structure pour stocker l'état et les caractéristiques d'un flux."""
    def __init__(self, start_time):
        self.start_time = start_time
        self.last_time = start_time
        self.BYTES = 0      
        self.BYTES_REV = 0  
        self.PACKETS = 0    
        self.PACKETS_REV = 0 
        self.fwd_timestamps = []  # IAT entre paquets forward
        self.rev_timestamps = []  # IAT entre paquets backward
        self.all_packet_times = []  # Tous les timestamps pour flow IAT
        self.last_fwd_time = 0
        self.last_rev_time = 0
        self.idle_periods = []
        self.active_periods = []
        self.last_packet_time = start_time
        self.current_active_start = start_time  # Début de la période active courante
        self.IDLE_THRESHOLD = 1.0  # Seuil pour considérer une période comme idle (1 seconde)

    def update_flow(self, packet, direction, current_time):
        """Met à jour les compteurs du flux avec un nouveau paquet."""
        length = len(packet) if IP in packet else len(packet)
        
        # Calculer l'inter-arrival time depuis le dernier paquet
        if self.last_packet_time != self.start_time:
            iat = current_time - self.last_packet_time
            
            # Si l'IAT dépasse le seuil, on a une période idle
            if iat > self.IDLE_THRESHOLD:
                # Enregistrer la période active précédente
                active_duration = self.last_packet_time - self.current_active_start
                if active_duration > 0:
                    self.active_periods.append(float(active_duration))
                
                # Enregistrer la période idle
                self.idle_periods.append(float(iat))
                
                # Nouvelle période active commence maintenant
                self.current_active_start = current_time
        
        # Enregistrer le timestamp pour le flow IAT
        self.all_packet_times.append(current_time)
        self.last_packet_time = current_time

        if direction == 'forward':
            self.BYTES += length
            self.PACKETS += 1
            if self.last_fwd_time != 0:
                fwd_iat = current_time - self.last_fwd_time
                if fwd_iat > 0:  # Éviter les IAT négatifs ou nuls
                    self.fwd_timestamps.append(float(fwd_iat))
            self.last_fwd_time = current_time
        else:
            self.BYTES_REV += length
            self.PACKETS_REV += 1
            if self.last_rev_time != 0:
                rev_iat = current_time - self.last_rev_time
                if rev_iat > 0:  # Éviter les IAT négatifs ou nuls
                    self.rev_timestamps.append(float(rev_iat))
            self.last_rev_time = current_time
            
        self.last_time = current_time

    def calculate_features(self):
        """Calcule les 23 caractéristiques finales dans l'ordre."""
        # Duration
        duration = max(0.0, float(self.last_time - self.start_time))
        
        # Forward IAT features (total_fiat, min_fiat, max_fiat, mean_fiat)
        if len(self.fwd_timestamps) > 0:
            fwd_iat = np.array(self.fwd_timestamps, dtype=np.float64)
            total_fiat = float(np.sum(fwd_iat))
            min_fiat = float(np.min(fwd_iat))
            max_fiat = float(np.max(fwd_iat))
            mean_fiat = float(np.mean(fwd_iat))
        else:
            total_fiat, min_fiat, max_fiat, mean_fiat = 0.0, 0.0, 0.0, 0.0

        # Backward IAT features (total_biat, min_biat, max_biat, mean_biat)
        if len(self.rev_timestamps) > 0:
            rev_iat = np.array(self.rev_timestamps, dtype=np.float64)
            total_biat = float(np.sum(rev_iat))
            min_biat = float(np.min(rev_iat))
            max_biat = float(np.max(rev_iat))
            mean_biat = float(np.mean(rev_iat))
        else:
            total_biat, min_biat, max_biat, mean_biat = 0.0, 0.0, 0.0, 0.0

        # Flow IAT features (calculé à partir de tous les paquets)
        if len(self.all_packet_times) > 1:
            # Calculer les IAT entre paquets consécutifs
            sorted_times = sorted(self.all_packet_times)
            flow_iats = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times)-1)]
            flow_iats = [iat for iat in flow_iats if iat > 0]  # Filtrer les IAT <= 0
            
            if len(flow_iats) > 0:
                flow_iat = np.array(flow_iats, dtype=np.float64)
                min_flowiat = float(np.min(flow_iat))
                max_flowiat = float(np.max(flow_iat))
                mean_flowiat = float(np.mean(flow_iat))
                std_flowiat = float(np.std(flow_iat)) if len(flow_iat) > 1 else 0.0
            else:
                min_flowiat, max_flowiat, mean_flowiat, std_flowiat = 0.0, 0.0, 0.0, 0.0
        else:
            min_flowiat, max_flowiat, mean_flowiat, std_flowiat = 0.0, 0.0, 0.0, 0.0
            
        # Packets and Bytes per second
        total_packets = self.PACKETS + self.PACKETS_REV
        total_bytes = self.BYTES + self.BYTES_REV
        if duration > 0:
            flowPktsPerSecond = float(total_packets / duration)
            flowBytesPerSecond = float(total_bytes / duration)
        else:
            flowPktsPerSecond = float(total_packets)
            flowBytesPerSecond = float(total_bytes)

        # Active time features - ajouter la dernière période active en cours
        active_list = self.active_periods.copy()
        final_active = self.last_time - self.current_active_start
        if final_active > 0:
            active_list.append(float(final_active))
            
        if len(active_list) > 0:
            active_array = np.array(active_list, dtype=np.float64)
            min_active = float(np.min(active_array))
            mean_active = float(np.mean(active_array))
            max_active = float(np.max(active_array))
            std_active = float(np.std(active_array)) if len(active_array) > 1 else 0.0
        else:
            # Si pas de période active enregistrée, utiliser la durée totale
            min_active = duration
            mean_active = duration
            max_active = duration
            std_active = 0.0

        # Idle time features
        if len(self.idle_periods) > 0:
            idle_array = np.array(self.idle_periods, dtype=np.float64)
            min_idle = float(np.min(idle_array))
            mean_idle = float(np.mean(idle_array))
            max_idle = float(np.max(idle_array))
            std_idle = float(np.std(idle_array)) if len(idle_array) > 1 else 0.0
        else:
            min_idle, mean_idle, max_idle, std_idle = 0.0, 0.0, 0.0, 0.0
        
        # Construire le vecteur de features dans l'ordre exact
        feature_vector_list = [
            duration,           # 0: duration
            total_fiat,         # 1: total_fiat
            total_biat,         # 2: total_biat
            min_fiat,           # 3: min_fiat
            min_biat,           # 4: min_biat
            max_fiat,           # 5: max_fiat
            max_biat,           # 6: max_biat
            mean_fiat,          # 7: mean_fiat
            mean_biat,          # 8: mean_biat
            flowPktsPerSecond,  # 9: flowPktsPerSecond
            flowBytesPerSecond, # 10: flowBytesPerSecond
            min_flowiat,        # 11: min_flowiat
            max_flowiat,        # 12: max_flowiat
            mean_flowiat,       # 13: mean_flowiat
            std_flowiat,        # 14: std_flowiat
            min_active,         # 15: min_active
            mean_active,        # 16: mean_active
            max_active,         # 17: max_active
            std_active,         # 18: std_active
            min_idle,           # 19: min_idle
            mean_idle,          # 20: mean_idle
            max_idle,           # 21: max_idle
            std_idle            # 22: std_idle
        ]
        
        # Nettoyer les valeurs NaN et Inf
        cleaned_features = []
        for x in feature_vector_list:
            if isinstance(x, (float, np.floating)):
                if math.isnan(x) or math.isinf(x):
                    cleaned_features.append(0.0)
                else:
                    cleaned_features.append(float(x))
            else:
                cleaned_features.append(float(x))
        
        return cleaned_features


# ============================================================================
# FONCTIONS DE SNIFFING ET CLASSIFICATION
# ============================================================================

def get_flow_quintuple(packet):
    """Extrait la quintuple pour identifier un flux."""
    if IP in packet:
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
    return None, None, None, None


def detect_monitored_clients(packet) -> List[str]:
    """Retourne la liste des IP surveillées impliquées dans le paquet."""
    clients = []
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_src in MONITORED_CLIENTS:
            clients.append(ip_src)
        if ip_dst in MONITORED_CLIENTS and ip_dst not in clients:
            clients.append(ip_dst)
    return clients


def classify_and_enqueue(flow_data, flow_key, client_ip, dest_ip, flow_clients=None):
    """Calcule les caractéristiques et place le résultat dans la queue."""
    global model, label_encoder, result_queue

    feature_vector_list = flow_data.calculate_features()
    X_predict = pd.DataFrame([feature_vector_list], columns=FEATURE_COLUMNS)
    X_predict = X_predict.replace([np.inf, -np.inf], np.nan).fillna(0)

    prediction_label = "UNKNOWN"
    confidence = 0.0
    all_probabilities = {}

    try:
        # Obtenir les probabilités pour toutes les classes
        probabilities = model.predict_proba(X_predict)[0]
        classes = label_encoder.classes_
        
        # Créer un dictionnaire de toutes les probabilités
        all_probabilities = {cls: round(float(prob) * 100, 2) for cls, prob in zip(classes, probabilities)}
        
        # Trouver la classe avec la plus haute probabilité
        max_prob_idx = np.argmax(probabilities)
        confidence = float(probabilities[max_prob_idx]) * 100
        prediction_label = classes[max_prob_idx]
        
        # Si la confiance est trop basse, marquer comme incertain
        if confidence < MIN_CONFIDENCE_THRESHOLD * 100:
            prediction_label = f"{prediction_label} (?)"
            
    except Exception as e:
        prediction_label = "UNKNOWN"
        confidence = 0.0
        print(f"Erreur de classification: {e}")

    volume_bytes = flow_data.BYTES + flow_data.BYTES_REV
    duration = flow_data.last_time - flow_data.start_time
    
    # Déterminer le niveau de confiance
    if confidence >= 80:
        confidence_level = "high"
    elif confidence >= 50:
        confidence_level = "medium"
    else:
        confidence_level = "low"

    result = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'label': prediction_label,
        'confidence': round(confidence, 1),
        'confidence_level': confidence_level,
        'all_probabilities': all_probabilities,
        'volume': volume_bytes,
        'client_ip': client_ip,
        'dest_ip': dest_ip,
        'dest_port': flow_key[3],
        'protocol': 'TCP' if flow_key[4] == 6 else 'UDP',
        'duration': round(duration, 2),
        'packets': flow_data.PACKETS + flow_data.PACKETS_REV,
        'is_malware': prediction_label.replace(' (?)', '') in ['ZEUS', 'TINBA', 'MIUREF', 'NERIS', 'NSIS', 'VIRUT'],
        'monitored_clients': flow_clients or []
    }
    
    result_queue.put(result)


def process_packet(packet):
    """Callback Scapy pour traiter chaque paquet."""
    global local_flows
    
    quintuple, direction, client_ip, dest_ip = get_flow_quintuple(packet)
    if not quintuple:
        return
    monitored_flow_clients = []
    if MONITORED_CLIENTS:
        monitored_flow_clients = detect_monitored_clients(packet)
        if len(monitored_flow_clients) == 0:
            return
        
    flow_key = quintuple
    current_time = packet.time
    
    if flow_key not in local_flows:
        local_flows[flow_key] = FlowData(start_time=current_time)
    if flow_key not in flow_client_map:
        flow_client_map[flow_key] = set(monitored_flow_clients)
    else:
        flow_client_map[flow_key].update(monitored_flow_clients)
        
    flow = local_flows[flow_key]
    flow.update_flow(packet, direction, current_time=current_time)

    # Classification sur fin de connexion TCP (FIN ou RST)
    if flow_key[4] == 6 and TCP in packet and (packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04):
        clients_list = list(flow_client_map.get(flow_key, []))
        classify_and_enqueue(flow, flow_key, client_ip, dest_ip, clients_list)
        del local_flows[flow_key]
        flow_client_map.pop(flow_key, None)
        return

    # Classification après seuil de paquets
    if (flow.PACKETS + flow.PACKETS_REV) >= CLASSIFY_PACKET_THRESHOLD:
        clients_list = list(flow_client_map.get(flow_key, []))
        classify_and_enqueue(flow, flow_key, client_ip, dest_ip, clients_list)
        del local_flows[flow_key]
        flow_client_map.pop(flow_key, None)


def clean_expired_flows():
    """Nettoie et classifie les flux expirés."""
    global local_flows
    
    while sniffer_running:
        flows_to_classify = []
        current_time = time.time()
        
        for key, flow in list(local_flows.items()):
            if current_time - flow.last_time > TIMEOUT_FLOW:
                flows_to_classify.append((key, flow))

        for key, flow in flows_to_classify:
            if key in local_flows:
                client_ip = key[0]
                dest_ip = key[2]
                clients_list = list(flow_client_map.get(key, []))
                classify_and_enqueue(local_flows[key], key, client_ip, dest_ip, clients_list)
                del local_flows[key]
                flow_client_map.pop(key, None)
        
        time.sleep(1)


def sniffer_thread_func(interface):
    """Thread de capture de paquets."""
    global sniffer_running
    try:
        print(f"🔍 Démarrage du sniffer sur {interface}...")
        sniff(iface=interface, prn=process_packet, store=0, stop_filter=lambda x: not sniffer_running)
    except Exception as e:
        print(f"❌ Erreur sniffer: {e}")


# ============================================================================
# APPLICATION FASTAPI
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application."""
    global model, label_encoder, sniffer_running
    
    # Startup
    try:
        print("📦 Chargement du modèle ML...")
        model = joblib.load(MODEL_FILENAME)
        label_encoder = joblib.load(ENCODER_FILENAME)
        print("✅ Modèle chargé avec succès!")
        print(f"   Classes: {list(label_encoder.classes_)}")
    except FileNotFoundError:
        print("❌ ERREUR: Modèle non trouvé! Exécutez d'abord train_classifer.py")
        model = None
        label_encoder = None
    
    # Démarrer la tâche de mise à jour
    asyncio.create_task(process_results_loop())
    asyncio.create_task(broadcast_history_loop())
    
    yield
    
    # Shutdown
    sniffer_running = False
    print("👋 Arrêt de l'application...")


app = FastAPI(title="🔍 AI Application Tracker", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,                                                                                                                                                                                                                                                                                                        
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# BOUCLES ASYNCHRONES
# ============================================================================

async def process_results_loop():
    """Traite les résultats de classification et les agrège dans le buffer de la minute."""
    global stats_data, current_minute_buffer
    
    while True:
        while not result_queue.empty():
            result = result_queue.get()
            
            # Initialiser le buffer si c'est le premier flux de la minute
            if current_minute_buffer['start_time'] is None:
                current_minute_buffer['start_time'] = datetime.now()
            
            # Mise à jour des statistiques globales
            stats_data['total_flows'] += 1
            stats_data['total_volume_bytes'] += result['volume']
            
            # Nettoyer le label (enlever le "(?)" pour les stats)
            clean_label = result['label'].replace(' (?)', '')
            
            stats_data['volume_by_type'][clean_label] += result['volume']
            stats_data['volume_by_ip'][result['client_ip']] += result['volume']
            stats_data['flows_by_ip'][result['client_ip']] += 1
            stats_data['flows_by_type'][clean_label] += 1
            stats_data['usage_by_dest'][result['dest_ip']] += result['duration']
            
            if result['is_malware']:
                stats_data['malware_alerts'] += 1
                stats_data['malware_by_ip'][result['client_ip']] += 1
                current_minute_buffer['malware_detected'] = True
            
            # Agréger dans le buffer de la minute courante
            current_minute_buffer['flows'].append(result)
            current_minute_buffer['apps_count'][clean_label] += 1
            current_minute_buffer['apps_confidence'][clean_label].append(result.get('confidence', 0))
            current_minute_buffer['destinations'][result['dest_ip']] += 1
            current_minute_buffer['total_volume'] += result['volume']

            # Mise à jour côté clients surveillés
            monitored_clients = result.get('monitored_clients', [])
            for client_ip in monitored_clients:
                client_buffer = client_buffers[client_ip]
                if client_buffer['start_time'] is None:
                    client_buffer['start_time'] = datetime.now()

                client_buffer['flows'].append(result)
                client_buffer['apps_count'][clean_label] += 1
                client_buffer['apps_confidence'][clean_label].append(result.get('confidence', 0))
                client_buffer['destinations'][result['dest_ip']] += 1
                client_buffer['total_volume'] += result['volume']
                if result['is_malware']:
                    client_buffer['malware_detected'] = True

                stats = per_client_stats[client_ip]
                stats['total_flows'] += 1
                stats['total_volume_bytes'] += result['volume']
                if result['is_malware']:
                    stats['malware_alerts'] += 1
                stats['app_distribution'][clean_label] += 1
                stats['protocols'][result['protocol']] += 1
                stats['destinations'][result['dest_ip']] += 1
                stats['confidence_sum'] += result.get('confidence', 0)
                stats['confidence_count'] += 1
                stats['last_update'] = datetime.now()
                
                # Calcul du débit (bandwidth)
                if stats['session_start'] is None:
                    stats['session_start'] = time.time()
                
                # Durée de session en secondes
                session_duration = time.time() - stats['session_start']
                stats['session_duration_seconds'] = session_duration
                
                # Calcul du débit : bytes/seconde puis conversion en Mbps
                if session_duration > 0:
                    bytes_per_second = stats['total_volume_bytes'] / session_duration
                    stats['bandwidth_bytes_per_second'] = bytes_per_second
                    # Conversion en Mbps : (bytes * 8) / 1_000_000 = Megabits
                    stats['bandwidth_mbps'] = round((bytes_per_second * 8) / 1_000_000, 3)
        
        await asyncio.sleep(0.5)


async def broadcast_history_loop():
    """Toutes les 60 secondes, crée un enregistrement d'historique avec l'app dominante."""
    global stats_data, current_minute_buffer
    
    while True:
        await asyncio.sleep(HISTORY_UPDATE_INTERVAL)
        
        timestamp = datetime.now().strftime("%H:%M")
        
        # Créer l'enregistrement de la minute si on a des données
        if current_minute_buffer['apps_count']:
            minute_record = build_minute_record_from_buffer(current_minute_buffer, timestamp)

            stats_data['minute_history'].append(minute_record)
            if len(stats_data['minute_history']) > 60:
                stats_data['minute_history'] = stats_data['minute_history'][-60:]

            snapshot = {
                'time': timestamp,
                'total_flows': stats_data['total_flows'],
                'volume_mb': round(stats_data['total_volume_bytes'] / (1024*1024), 2),
                'malware_alerts': stats_data['malware_alerts'],
                'minute_flows': minute_record['total_flows']
            }

            stats_data['timeline'].append(snapshot)
            if len(stats_data['timeline']) > 60:
                stats_data['timeline'] = stats_data['timeline'][-60:]

            await broadcast_to_websockets({
                'type': 'minute_update',
                'data': {
                    'record': minute_record,
                    'stats': {
                        'total_flows': stats_data['total_flows'],
                        'malware_alerts': stats_data['malware_alerts'],
                        'volume_mb': round(stats_data['total_volume_bytes'] / (1024*1024), 2)
                    },
                    'apps_distribution': dict(stats_data['flows_by_type'])
                }
            })
            print(f"📊 {timestamp} - App dominante: {minute_record['app']} ({minute_record['confidence']:.1f}%)")

        # Agrégation par client
        for client_ip in list(MONITORED_CLIENTS):
            buffer = client_buffers[client_ip]
            if buffer['apps_count']:
                client_record = build_minute_record_from_buffer(buffer, timestamp)
                per_client_history[client_ip].append(client_record)
                if len(per_client_history[client_ip]) > 60:
                    per_client_history[client_ip] = per_client_history[client_ip][-60:]

                stats = per_client_stats[client_ip]
                stats['timeline'].append({
                    'time': timestamp,
                    'flows': client_record['total_flows'],
                    'volume_kb': client_record['volume_kb'],
                    'app': client_record['app'],
                    'confidence': client_record['confidence']
                })
                if len(stats['timeline']) > 120:
                    stats['timeline'] = stats['timeline'][-120:]

                payload = {
                    'record': client_record,
                    'stats': build_client_stats_snapshot(client_ip)
                }
                await broadcast_to_websockets({
                    'type': 'client_update',
                    'client': client_ip,
                    'data': payload
                })

            client_buffers[client_ip] = create_minute_buffer()

        # Réinitialiser le buffer global pour la prochaine minute
        current_minute_buffer = create_minute_buffer()


async def broadcast_to_websockets(message: dict):
    """Envoie un message à tous les clients WebSocket."""
    disconnected = []
    for ws in connected_websockets:
        try:
            await ws.send_json(message)
        except:
            disconnected.append(ws)
    
    for ws in disconnected:
        if ws in connected_websockets:
            connected_websockets.remove(ws)


# ============================================================================
# ROUTES API
# ============================================================================


class ClientConfig(BaseModel):
    clients: List[str]


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Page principale du dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@app.post("/api/configure-clients")
async def configure_clients(config: ClientConfig):
    """Configure dynamiquement les clients surveillés."""
    global MONITORED_CLIENTS
    cleaned_clients = [ip.strip() for ip in config.clients if ip.strip()]
    MONITORED_CLIENTS = set(cleaned_clients)

    for ip in list(per_client_history.keys()):
        if ip not in MONITORED_CLIENTS:
            per_client_history.pop(ip, None)
    for ip in list(per_client_stats.keys()):
        if ip not in MONITORED_CLIENTS:
            per_client_stats.pop(ip, None)
    for ip in list(client_buffers.keys()):
        if ip not in MONITORED_CLIENTS:
            client_buffers.pop(ip, None)

    for ip in MONITORED_CLIENTS:
        per_client_history[ip]
        per_client_stats[ip]
        client_buffers[ip]

    await broadcast_to_websockets({
        'type': 'clients_update',
        'clients': list(MONITORED_CLIENTS)
    })

    return {"success": True, "clients": list(MONITORED_CLIENTS)}


def ensure_client_exists(ip: str):
    if MONITORED_CLIENTS and ip not in MONITORED_CLIENTS:
        raise HTTPException(status_code=404, detail="Client non configuré")


@app.get("/api/clients")
async def list_clients():
    """Retourne la liste des IP surveillées."""
    return {"clients": list(MONITORED_CLIENTS)}


@app.get("/api/clients/ranking")
async def get_clients_ranking():
    """Retourne le classement des clients par volume de consommation et débit."""
    ranking = []
    for ip in MONITORED_CLIENTS:
        stats = per_client_stats.get(ip, create_client_stats())
        volume_bytes = stats.get('total_volume_bytes', 0)
        bandwidth_mbps = stats.get('bandwidth_mbps', 0)
        session_duration = stats.get('session_duration_seconds', 0)
        
        ranking.append({
            'ip': ip,
            'volume_bytes': volume_bytes,
            'volume_mb': round(volume_bytes / (1024 * 1024), 2),
            'volume_gb': round(volume_bytes / (1024 * 1024 * 1024), 3),
            'total_flows': stats.get('total_flows', 0),
            'malware_alerts': stats.get('malware_alerts', 0),
            'bandwidth_mbps': round(bandwidth_mbps, 3),
            'bandwidth_kbps': round(bandwidth_mbps * 1000, 1),
            'session_duration_seconds': round(session_duration, 1),
            'session_duration_formatted': format_duration(session_duration)
        })
    
    # Trier par volume décroissant
    ranking.sort(key=lambda x: x['volume_bytes'], reverse=True)
    
    # Ajouter le rang et le pourcentage
    total_volume = sum(c['volume_bytes'] for c in ranking)
    total_bandwidth = sum(c['bandwidth_mbps'] for c in ranking)
    for i, client in enumerate(ranking):
        client['rank'] = i + 1
        client['percentage'] = round((client['volume_bytes'] / total_volume * 100), 1) if total_volume > 0 else 0
        client['bandwidth_percentage'] = round((client['bandwidth_mbps'] / total_bandwidth * 100), 1) if total_bandwidth > 0 else 0
    
    return {
        "ranking": ranking,
        "total_bandwidth_mbps": round(total_bandwidth, 3),
        "total_volume_mb": round(total_volume / (1024 * 1024), 2),
        "total_clients": len(ranking)
    }


@app.get("/api/client/{ip}/history")
async def get_client_history(ip: str, limit: int = 60):
    """Historique des 60 dernières minutes pour un client."""
    ensure_client_exists(ip)
    history = per_client_history.get(ip, [])
    return {
        "client": ip,
        "history": history[-limit:]
    }


@app.get("/api/client/{ip}/flows/{minute}")
async def get_client_flows(ip: str, minute: str):
    """Flux détaillés d'une minute donnée pour un client."""
    ensure_client_exists(ip)
    for record in per_client_history.get(ip, []):
        if record['time'] == minute:
            return {
                "client": ip,
                "time": minute,
                "flows": record.get('flows_detail', [])
            }
    raise HTTPException(status_code=404, detail="Minute non trouvée")


@app.get("/api/client/{ip}/stats")
async def get_client_stats_endpoint(ip: str):
    """Statistiques agrégées d'un client."""
    ensure_client_exists(ip)
    snapshot = build_client_stats_snapshot(ip)
    history = per_client_history.get(ip, [])
    last_record = history[-1] if history else None
    return {
        "client": ip,
        "stats": snapshot,
        "latest_record": last_record
    }


@app.post("/api/start")
async def start_sniffer(interface: str = Form(default=DEFAULT_INTERFACE)):
    """Démarre le sniffer sur l'interface spécifiée."""
    global sniffer_running, network_interface
    
    if model is None:
        return {"success": False, "error": "Modèle ML non chargé"}
    
    if sniffer_running:
        return {"success": False, "error": "Sniffer déjà en cours"}
    
    network_interface = interface
    sniffer_running = True
    
    # Démarrer les threads
    threading.Thread(target=sniffer_thread_func, args=(interface,), daemon=True).start()
    threading.Thread(target=clean_expired_flows, daemon=True).start()
    
    return {"success": True, "message": f"Sniffer démarré sur {interface}"}


@app.post("/api/stop")
async def stop_sniffer():
    """Arrête le sniffer."""
    global sniffer_running
    sniffer_running = False
    return {"success": True, "message": "Sniffer arrêté"}


@app.get("/api/status")
async def get_status():
    """Retourne le statut du sniffer."""
    return {
        "running": sniffer_running,
        "interface": network_interface,
        "model_loaded": model is not None
    }


@app.get("/api/history")
async def get_history(limit: int = 60):
    """Retourne l'historique par minute (1 entrée = 1 minute)."""
    # Retourner sans les détails des flux pour alléger
    history_light = []
    for record in stats_data['minute_history'][-limit:]:
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
        "history": history_light,
        "total": len(stats_data['minute_history'])
    }


@app.get("/api/history/{time_key}/flows")
async def get_minute_flows(time_key: str):
    """Retourne les flux détaillés d'une minute spécifique."""
    for record in stats_data['minute_history']:
        if record['time'] == time_key:
            return {
                "time": record['time'],
                "app": record['app'],
                "total_flows": record['total_flows'],
                "flows": record.get('flows_detail', [])
            }
    return {"error": "Minute non trouvée", "flows": []}


@app.get("/api/minute-details/{time}")
async def get_minute_details(time: str):
    """Retourne les détails complets d'une minute spécifique pour le modal."""
    for record in stats_data['minute_history']:
        if record['time'] == time:
            flows = record.get('flows_detail', [])
            
            # Calculer la confiance moyenne
            confidences = [f.get('confidence', 0) for f in flows]
            avg_confidence = round(sum(confidences) / len(confidences), 1) if confidences else 0
            
            # Enrichir les données de flux pour l'affichage
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
                "success": True,
                "time": time,
                "dominant_app": record['app'],
                "total_flows": record['total_flows'],
                "average_confidence": avg_confidence,
                "all_apps": record.get('all_apps', {}),
                "flows": enriched_flows
            }
    
    return {"success": False, "error": "Minute non trouvée"}


@app.get("/api/stats")
async def get_stats():
    """Retourne les statistiques globales."""
    return {
        "total_flows": stats_data['total_flows'],
        "malware_alerts": stats_data['malware_alerts'],
        "total_volume_mb": round(stats_data['total_volume_bytes'] / (1024*1024), 2),
        "flows_by_type": dict(stats_data['flows_by_type']),
        "volume_by_type_mb": {k: round(v/(1024*1024), 2) for k, v in stats_data['volume_by_type'].items()},
        "top_destinations": dict(sorted(stats_data['usage_by_dest'].items(), key=lambda x: x[1], reverse=True)[:10]),
        "timeline": stats_data['timeline'][-20:]
    }


@app.get("/api/apps")
async def get_apps():
    """Retourne les applications détectées par type de trafic."""
    apps = []
    for label, count in sorted(stats_data['flows_by_type'].items(), key=lambda x: x[1], reverse=True):
        volume_mb = round(stats_data['volume_by_type'].get(label, 0) / (1024*1024), 2)
        is_malware = label in ['ZEUS', 'TINBA', 'MIUREF', 'NERIS', 'NSIS', 'VIRUT']
        apps.append({
            "name": label,
            "flows": count,
            "volume_mb": volume_mb,
            "is_malware": is_malware,
            "category": get_app_category(label)
        })
    return apps


def get_app_category(label: str) -> str:
    """Retourne la catégorie d'une application."""
    categories = {
        # Malwares
        'ZEUS': '🦠 Malware (Banking Trojan)',
        'TINBA': '🦠 Malware (Banking Trojan)',
        'MIUREF': '🦠 Malware (Backdoor)',
        'NERIS': '🦠 Malware (Botnet)',
        'NSIS': '🦠 Malware',
        'VIRUT': '🦠 Malware (Virus)',
        # Applications légitimes
        'BITTORRENT': '📥 P2P / Torrent',
        'FTP': '📁 Transfert de fichiers',
        'GMAIL': '📧 Email',
        'GOOGLE': '🔍 Recherche Web',
        'HTTP': '🌐 Navigation Web',
        'HTTPS': '🔒 Navigation Web (Sécurisé)',
        'MYSQL': '🗃️ Base de données',
        'OUTLOOK': '📧 Email',
        'SKYPE': '💬 Communication',
        'SMB': '📁 Partage de fichiers',
        'WEIBO': '📱 Réseaux Sociaux',
        'WORLDOFWARCRAFT': '🎮 Jeux en ligne',
        'FACETIME': '📹 Appel vidéo',
    }
    return categories.get(label, '📦 Autre')


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket pour les mises à jour en temps réel."""
    await websocket.accept()
    connected_websockets.append(websocket)
    
    try:
        # Envoyer l'état initial
        await websocket.send_json({
            'type': 'init',
            'data': {
                'running': sniffer_running,
                'history': stats_data['minute_history'][-30:],
                'apps_distribution': dict(stats_data['flows_by_type']),
                'clients': list(MONITORED_CLIENTS),
                'client_history': {ip: per_client_history[ip][-30:] for ip in MONITORED_CLIENTS},
                'client_stats': {ip: build_client_stats_snapshot(ip) for ip in MONITORED_CLIENTS},
                'stats': {
                    'total_flows': stats_data['total_flows'],
                    'malware_alerts': stats_data['malware_alerts'],
                    'total_volume_mb': round(stats_data['total_volume_bytes'] / (1024*1024), 2)
                }
            }
        })
        
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


# ============================================================================
# TEMPLATE HTML DU DASHBOARD
# ============================================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 AI Application Tracker</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
            color: #eee;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0, 0, 0, 0.3);
            padding: 20px;
            text-align: center;
            border-bottom: 2px solid #00d9ff33;
        }
        
        .header h1 {
            font-size: 2em;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .controls {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        .control-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        input[type="text"] {
            padding: 10px 15px;
            border: 1px solid #00d9ff44;
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.3);
            color: #fff;
            font-size: 1em;
        }
        
        button {
            padding: 10px 25px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-start {
            background: linear-gradient(135deg, #00ff88, #00d9ff);
            color: #000;
            font-weight: bold;
        }
        
        .btn-stop {
            background: linear-gradient(135deg, #ff4444, #ff6b6b);
            color: #fff;
            font-weight: bold;
        }
        
        button:hover { transform: scale(1.05); }
        button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        
        .status-badge {
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        
        .status-running { background: #00ff8833; color: #00ff88; border: 1px solid #00ff88; }
        .status-stopped { background: #ff444433; color: #ff4444; border: 1px solid #ff4444; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px;
            max-width: 1200px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .stat-card {
            background: rgba(0, 217, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(0, 217, 255, 0.2);
        }
        
        .stat-card.alert {
            background: rgba(255, 68, 68, 0.1);
            border-color: rgba(255, 68, 68, 0.3);
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00d9ff;
        }
        
        .stat-card.alert .stat-value { color: #ff4444; }
        
        .stat-label {
            font-size: 0.9em;
            color: #888;
            margin-top: 5px;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .card-full {
            grid-column: span 2;
        }
        
        .card h2 {
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #00d9ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        /* Historique simplifié - 1 ligne par minute */
        .history-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .history-table th {
            text-align: left;
            padding: 12px;
            background: rgba(0, 217, 255, 0.1);
            color: #00d9ff;
            font-weight: 600;
        }
        
        .history-table td {
            padding: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .history-table tbody tr {
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .history-table tbody tr:hover {
            background: rgba(0, 217, 255, 0.1);
            transform: scale(1.01);
        }
        
        .history-table tr.malware {
            background: rgba(255, 68, 68, 0.1);
        }
        
        .history-table tr.malware:hover {
            background: rgba(255, 68, 68, 0.2);
        }
        
        .history-table tr.malware td {
            color: #ff6b6b;
        }
        
        .click-hint {
            font-size: 0.75em;
            color: #666;
            margin-left: 5px;
        }
        
        .app-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: 600;
        }
        
        .app-badge.normal {
            background: rgba(0, 255, 136, 0.15);
            color: #00ff88;
        }
        
        .app-badge.malware {
            background: rgba(255, 68, 68, 0.2);
            color: #ff4444;
        }
        
        .confidence {
            font-size: 0.9em;
            padding: 3px 10px;
            border-radius: 12px;
        }
        
        .confidence.high {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
        }
        
        .confidence.medium {
            background: rgba(255, 217, 61, 0.2);
            color: #ffd93d;
        }
        
        .confidence.low {
            background: rgba(255, 68, 68, 0.2);
            color: #ff6b6b;
        }
        
        .ip-text {
            font-family: 'Consolas', monospace;
            color: #888;
            font-size: 0.9em;
        }
        
        .chart-container {
            position: relative;
            height: 350px;
        }
        
        .no-data {
            color: #666;
            text-align: center;
            padding: 60px 20px;
            font-style: italic;
        }
        
        .live-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .live-dot {
            width: 10px;
            height: 10px;
            background: #00ff88;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .update-timer {
            text-align: center;
            padding: 10px;
            color: #666;
            font-size: 0.85em;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            margin-top: 15px;
        }
        
        .history-scroll {
            max-height: 400px;
            overflow-y: auto;
        }
        
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: rgba(255, 255, 255, 0.05); }
        ::-webkit-scrollbar-thumb { background: #00d9ff44; border-radius: 4px; }
        
        @media (max-width: 900px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            .card-full {
                grid-column: span 1;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        /* Styles pour les lignes cliquables */
        .clickable-row {
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
        }
        .clickable-row:hover {
            background: rgba(0, 217, 255, 0.15) !important;
            transform: scale(1.005);
        }
        
        /* Modal styles */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            backdrop-filter: blur(5px);
        }
        .modal-content {
            background: linear-gradient(145deg, #1a1a3e 0%, #0d0d1f 100%);
            border: 1px solid #00d9ff33;
            border-radius: 16px;
            width: 90%;
            max-width: 800px;
            max-height: 80vh;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 217, 255, 0.2);
        }

        /* ========== SECTION CONFIGURATION CLIENTS ========== */
        .config-section {
            max-width: 900px;
            margin: 30px auto;
            background: linear-gradient(145deg, rgba(15, 25, 45, 0.95) 0%, rgba(10, 18, 35, 0.98) 100%);
            border-radius: 20px;
            padding: 35px;
            border: 2px solid rgba(0, 217, 255, 0.25);
            box-shadow: 
                0 15px 50px rgba(0, 0, 0, 0.4),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            position: relative;
            overflow: hidden;
        }
        .config-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #00d9ff, #00ff88, #00d9ff);
        }
        .config-section h2 {
            margin: 0 0 30px 0;
            color: #fff;
            font-size: 1.5em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .config-grid {
            display: flex;
            gap: 30px;
            align-items: flex-start;
        }
        .config-field {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .config-field:first-child {
            flex: 0 0 180px;
        }
        .config-field:last-child {
            flex: 1;
        }
        .config-section label { 
            color: #00d9ff; 
            font-size: 0.95em; 
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .config-section input[type="number"] {
            width: 100%;
            padding: 16px 20px;
            border-radius: 12px;
            border: 2px solid rgba(0, 217, 255, 0.2);
            background: rgba(0, 0, 0, 0.5);
            color: #fff;
            font-size: 1.5em;
            font-weight: 700;
            text-align: center;
            transition: all 0.3s ease;
        }
        .config-section input[type="number"]:hover {
            border-color: rgba(0, 217, 255, 0.4);
        }
        .config-section textarea {
            width: 100%;
            padding: 16px 18px;
            border-radius: 12px;
            border: 2px solid rgba(0, 217, 255, 0.2);
            background: rgba(0, 0, 0, 0.5);
            color: #fff;
            font-size: 1.05em;
            resize: none;
            min-height: 70px;
            font-family: 'Consolas', 'Monaco', monospace;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }
        .config-section textarea::placeholder {
            color: rgba(255, 255, 255, 0.3);
        }
        .config-section textarea:hover {
            border-color: rgba(0, 217, 255, 0.4);
        }
        .config-section input:focus, .config-section textarea:focus {
            outline: none;
            border-color: #00d9ff;
            box-shadow: 
                0 0 20px rgba(0, 217, 255, 0.25),
                inset 0 0 10px rgba(0, 217, 255, 0.05);
        }
        .client-ip-hint {
            font-size: 0.8em;
            color: rgba(255, 255, 255, 0.5);
            margin-top: 8px;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .config-actions {
            display: flex;
            gap: 20px;
            margin-top: 30px;
            padding-top: 25px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            align-items: center;
        }
        .btn-primary {
            background: linear-gradient(135deg, #00ff88 0%, #00d9ff 100%);
            border: none;
            padding: 15px 35px;
            border-radius: 12px;
            cursor: pointer;
            font-weight: 700;
            font-size: 1em;
            color: #000;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 5px 20px rgba(0, 255, 136, 0.3);
        }
        .btn-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0, 255, 136, 0.5);
        }
        .btn-primary:active {
            transform: translateY(-1px);
        }
        .config-status { 
            color: #00ff88; 
            font-size: 0.95em;
            padding: 12px 20px;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 10px;
            border: 1px solid rgba(0, 255, 136, 0.3);
            display: none;
        }
        .config-status.visible {
            display: block;
            animation: fadeIn 0.3s ease;
        }
        .config-status.error {
            color: #ff6b6b;
            background: rgba(255, 68, 68, 0.1);
            border-color: rgba(255, 68, 68, 0.3);
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ========== SECTION CLASSEMENT VOLUME ========== */
        .volume-ranking-section {
            max-width: 900px;
            margin: 30px auto;
            background: linear-gradient(145deg, rgba(15, 25, 45, 0.95) 0%, rgba(10, 18, 35, 0.98) 100%);
            border-radius: 20px;
            padding: 25px 30px;
            border: 2px solid rgba(255, 215, 0, 0.25);
            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.4);
            position: relative;
            overflow: hidden;
        }
        .volume-ranking-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #ffd700, #ff8c00, #ffd700);
        }
        .volume-ranking-section h2 {
            margin: 0 0 20px 0;
            color: #ffd700;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .ranking-total {
            font-size: 0.9em;
            color: #888;
            margin-left: auto;
            font-weight: normal;
        }
        .ranking-total-bandwidth {
            font-size: 0.85em;
            color: #00d9ff;
            margin-left: 15px;
            padding: 3px 10px;
            background: rgba(0, 217, 255, 0.1);
            border-radius: 5px;
        }
        .ranking-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .ranking-item {
            display: grid;
            grid-template-columns: 50px 1fr 120px 120px 100px;
            align-items: center;
            gap: 15px;
            padding: 15px 20px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            transition: all 0.3s ease;
        }
        .ranking-item:hover {
            background: rgba(255, 215, 0, 0.05);
            border-color: rgba(255, 215, 0, 0.2);
            transform: translateX(5px);
        }
        .ranking-item.rank-1 {
            background: linear-gradient(90deg, rgba(255, 215, 0, 0.15), rgba(0, 0, 0, 0.3));
            border-color: rgba(255, 215, 0, 0.4);
        }
        .ranking-item.rank-2 {
            background: linear-gradient(90deg, rgba(192, 192, 192, 0.1), rgba(0, 0, 0, 0.3));
            border-color: rgba(192, 192, 192, 0.3);
        }
        .ranking-item.rank-3 {
            background: linear-gradient(90deg, rgba(205, 127, 50, 0.1), rgba(0, 0, 0, 0.3));
            border-color: rgba(205, 127, 50, 0.3);
        }
        .rank-badge {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.1em;
        }
        .rank-1 .rank-badge {
            background: linear-gradient(135deg, #ffd700, #ff8c00);
            color: #000;
            box-shadow: 0 4px 15px rgba(255, 215, 0, 0.4);
        }
        .rank-2 .rank-badge {
            background: linear-gradient(135deg, #c0c0c0, #a0a0a0);
            color: #000;
        }
        .rank-3 .rank-badge {
            background: linear-gradient(135deg, #cd7f32, #8b4513);
            color: #fff;
        }
        .rank-badge.default {
            background: rgba(255, 255, 255, 0.1);
            color: #888;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .ranking-ip {
            font-family: 'Consolas', monospace;
            font-size: 1.1em;
            color: #fff;
        }
        .ranking-volume {
            text-align: right;
        }
        .ranking-volume .value {
            font-size: 1.3em;
            font-weight: 700;
            color: #00d9ff;
        }
        .ranking-volume .unit {
            font-size: 0.85em;
            color: #888;
            margin-left: 3px;
        }
        .ranking-percent {
            text-align: center;
        }
        .ranking-percent .bar {
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 5px;
        }
        .ranking-percent .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        .ranking-percent .text {
            font-size: 0.85em;
            color: #888;
        }
        .ranking-bandwidth {
            text-align: center;
        }
        .ranking-bandwidth .value {
            font-size: 1.2em;
            font-weight: 700;
            color: #00ff88;
        }
        .ranking-bandwidth .unit {
            font-size: 0.75em;
            color: #888;
            margin-left: 2px;
        }
        .ranking-bandwidth .duration {
            font-size: 0.75em;
            color: #666;
            margin-top: 3px;
        }
        .no-ranking-data {
            text-align: center;
            padding: 30px;
            color: #666;
        }

        /* ========== SECTION PANELS CLIENTS ========== */
        .client-panels-wrapper {
            max-width: 1400px;
            margin: 30px auto;
            padding: 0 20px;
        }
        .client-panels-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .client-panels-header h2 {
            color: #00d9ff;
            font-size: 1.3em;
            margin: 0;
        }
        .client-count-badge {
            background: rgba(0, 217, 255, 0.2);
            color: #00d9ff;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        .client-panels {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 20px;
        }
        .client-panel {
            background: linear-gradient(145deg, rgba(255,255,255,0.05) 0%, rgba(0,0,0,0.2) 100%);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 18px;
            padding: 20px;
            transition: all 0.3s;
        }
        .client-panel:hover {
            border-color: rgba(0, 217, 255, 0.3);
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        .panel-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: flex-start;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .panel-header h3 {
            margin: 0;
            color: #fff;
            font-size: 1.2em;
            font-family: 'Consolas', monospace;
        }
        .panel-header p {
            margin: 5px 0 0 0;
            color: #888;
            font-size: 0.9em;
        }
        .panel-stats { 
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }
        .panel-stat { 
            background: rgba(0, 217, 255, 0.08);
            border-radius: 12px;
            padding: 15px 10px;
            text-align: center;
        }
        .panel-stat .label { 
            color: #888; 
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .panel-stat .value { 
            font-size: 1.5em; 
            font-weight: 700;
            color: #00d9ff;
            margin-top: 5px;
        }
        .mini-chart { 
            height: 140px; 
            margin-top: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 12px;
            padding: 10px;
        }
        
        /* Mini historique par client */
        .client-history-section {
            margin-top: 15px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }
        .client-history-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            background: rgba(0, 217, 255, 0.1);
            border-bottom: 1px solid rgba(0, 217, 255, 0.2);
        }
        .client-history-header h4 {
            margin: 0;
            font-size: 0.9em;
            color: #00d9ff;
        }
        .client-history-scroll {
            max-height: 200px;
            overflow-y: auto;
        }
        .client-history-scroll::-webkit-scrollbar {
            width: 5px;
        }
        .client-history-scroll::-webkit-scrollbar-thumb {
            background: rgba(0, 217, 255, 0.3);
            border-radius: 3px;
        }
        .mini-history-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8em;
        }
        .mini-history-table th {
            background: rgba(0, 0, 0, 0.3);
            color: #888;
            padding: 8px 10px;
            text-align: left;
            font-weight: 500;
            position: sticky;
            top: 0;
        }
        .mini-history-table td {
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        .mini-history-table .clickable-row {
            cursor: pointer;
            transition: background 0.2s;
        }
        .mini-history-table .clickable-row:hover {
            background: rgba(0, 217, 255, 0.1);
        }
        .mini-history-table .clickable-row.malware {
            background: rgba(255, 68, 68, 0.1);
        }
        .mini-history-table .clickable-row.malware:hover {
            background: rgba(255, 68, 68, 0.2);
        }
        .mini-app-badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .mini-app-badge.normal {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
        }
        .mini-app-badge.malware {
            background: rgba(255, 68, 68, 0.2);
            color: #ff6b6b;
        }
        .mini-confidence {
            font-weight: 600;
        }
        .mini-confidence.high { color: #00ff88; }
        .mini-confidence.medium { color: #ffd93d; }
        .mini-confidence.low { color: #ff6b6b; }
        
        .btn-secondary { 
            background: transparent;
            border: 1px solid #00d9ff;
            color: #00d9ff;
            border-radius: 8px;
            padding: 10px 18px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.3s;
        }
        .btn-secondary:hover {
            background: rgba(0, 217, 255, 0.1);
            transform: scale(1.02);
        }
        .no-clients-message {
            text-align: center;
            padding: 60px 20px;
            color: #666;
            font-size: 1.1em;
            background: rgba(255,255,255,0.02);
            border-radius: 15px;
            border: 2px dashed rgba(255,255,255,0.1);
        }
        .no-clients-message span {
            font-size: 3em;
            display: block;
            margin-bottom: 15px;
        }
            animation: modalSlide 0.3s ease;
        }
        @keyframes modalSlide {
            from { transform: translateY(-30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .modal-header {
            padding: 20px 25px;
            border-bottom: 1px solid #00d9ff33;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(0, 217, 255, 0.05);
        }
        .modal-header h3 {
            margin: 0;
            color: #00d9ff;
            font-size: 1.3em;
        }
        .modal-close {
            background: none;
            border: none;
            color: #888;
            font-size: 28px;
            cursor: pointer;
            padding: 0;
            line-height: 1;
            transition: color 0.2s, transform 0.2s;
        }
        .modal-close:hover {
            color: #ff6b6b;
            transform: rotate(90deg);
        }
        .modal-body {
            padding: 20px 25px;
            overflow-y: auto;
            max-height: 60vh;
        }
        .modal-summary {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .summary-item {
            background: rgba(255, 255, 255, 0.03);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .summary-item .value {
            font-size: 1.5em;
            font-weight: 600;
            color: #00d9ff;
        }
        .summary-item .label {
            color: #888;
            font-size: 0.85em;
            margin-top: 5px;
        }
        .flows-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .flow-item {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 15px;
            display: grid;
            grid-template-columns: 1fr 120px 100px;
            align-items: center;
            gap: 15px;
            transition: border-color 0.2s;
        }
        .flow-item:hover {
            border-color: #00d9ff44;
        }
        .flow-item.malware {
            border-color: #ff6b6b44;
            background: rgba(255, 68, 68, 0.05);
        }
        .flow-info {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .flow-ips {
            font-family: 'Consolas', monospace;
            font-size: 0.9em;
            color: #aaa;
        }
        .flow-ports {
            font-size: 0.8em;
            color: #666;
        }
        .flow-app {
            text-align: center;
        }
        .flow-confidence {
            text-align: right;
        }
        .no-flows {
            text-align: center;
            color: #666;
            padding: 40px;
            font-style: italic;
        }
    </style>
</head>
<body>
        <div class="header">
            <h1>🔍 AI Application Tracker</h1>
            <p style="color: #888; margin-top: 5px;">Historique des applications détectées par Intelligence Artificielle</p>
        
            <div class="controls">
                <div class="control-group">
                    <label style="color: #888;">Interface:</label>
                    <input type="text" id="interface" value="wlp3s0" placeholder="Interface réseau">
                </div>
                <button id="btnStart" class="btn-start" type="button">▶️ Démarrer</button>
                <button id="btnStop" class="btn-stop" type="button" disabled>⏹️ Arrêter</button>
                <span id="statusBadge" class="status-badge status-stopped">⚫ Arrêté</span>
            </div>
        </div>
    
        <section class="config-section">
            <h2>⚙️ Configuration des Clients à Surveiller</h2>
            <form id="clientConfigForm">
                <div class="config-grid">
                    <div class="config-field">
                        <label for="clientCount">📊 Nombre de clients</label>
                        <input type="number" id="clientCount" min="1" max="20" value="1">
                    </div>
                    <div class="config-field">
                        <label for="clientIps">🌐 Adresses IP des clients</label>
                        <textarea id="clientIps" rows="2" placeholder="Ex: 192.168.1.10, 192.168.1.14, 10.0.0.5"></textarea>
                        <span class="client-ip-hint">💡 Séparez les adresses IP par des virgules. Ex: 192.168.1.10, 192.168.1.20</span>
                    </div>
                </div>
                <div class="config-actions">
                    <button type="submit" class="btn-primary">✅ Valider la Configuration</button>
                    <div id="configStatus" class="config-status"></div>
                </div>
            </form>
        </section>
    
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalFlows">0</div>
                <div class="stat-label">Flux Total Analysés</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="uniqueApps">0</div>
                <div class="stat-label">Applications Détectées</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalVolume">0 MB</div>
                <div class="stat-label">Volume Total</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value" id="malwareAlerts">0</div>
                <div class="stat-label">🚨 Alertes Malware</div>
            </div>
        </div>

        <!-- Section Classement par Volume et Bande Passante -->
        <section class="volume-ranking-section" id="volumeRankingSection" style="display: none;">
            <h2>
                🏆 Classement par Consommation & Bande Passante
                <span class="ranking-total" id="rankingTotal">Total: 0 MB</span>
                <span class="ranking-total-bandwidth" id="rankingTotalBandwidth">⚡ 0 Mbps</span>
            </h2>
            <div class="ranking-list" id="rankingList">
                <div class="no-ranking-data">En attente de données...</div>
            </div>
        </section>
    
        <div class="client-panels-wrapper">
            <div class="client-panels-header">
                <h2>🖥️ Surveillance par Client</h2>
                <span class="client-count-badge" id="clientCountBadge">0 clients configurés</span>
            </div>
            <div class="client-panels" id="clientPanels">
                <div class="no-clients-message" id="noClientMessage">
                    <span>🖥️</span>
                    Configurez des clients ci-dessus pour démarrer la surveillance.
                </div>
            </div>
        </div>
    
        <div class="main-content">
            <div class="card card-full">
                <h2>
                    <span class="live-indicator">
                        <span class="live-dot"></span>
                    </span>
                    📜 Historique Global (1 entrée / minute)
                </h2>
                <div class="history-scroll">
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>⏰ Heure</th>
                                <th>🌐 Destination IP</th>
                                <th>📱 Application</th>
                                <th>📊 Confiance</th>
                                <th>📈 Flux</th>
                            </tr>
                        </thead>
                        <tbody id="historyBody">
                            <tr>
                                <td colspan="5" class="no-data">
                                    En attente de données... (mise à jour toutes les 60 secondes)
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div class="update-timer">
                    🔄 Prochaine mise à jour dans: <span id="countdown">60</span>s
                </div>
            </div>
        
            <div class="card">
                <h2>📊 Répartition des Applications</h2>
                <div class="chart-container">
                    <canvas id="pieChart"></canvas>
                </div>
            </div>
        
            <div class="card">
                <h2>📈 Évolution du Trafic</h2>
                <div class="chart-container">
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>
        </div>
    
    <!-- Modal pour les détails des flux -->
    <div id="flowModal" class="modal-overlay" style="display: none;" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h3>📊 Détails des flux - <span id="modalTime"></span></h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-summary">
                    <div class="summary-item">
                        <div class="value" id="modalTotalFlows">0</div>
                        <div class="label">Flux Total</div>
                    </div>
                    <div class="summary-item">
                        <div class="value" id="modalMainApp">-</div>
                        <div class="label">App Dominante</div>
                    </div>
                    <div class="summary-item">
                        <div class="value" id="modalAvgConf">0%</div>
                        <div class="label">Confiance Moyenne</div>
                    </div>
                </div>
                <h4 style="color: #00d9ff; margin-bottom: 15px;">🔍 Liste des flux analysés:</h4>
                <div id="flowsList" class="flows-list">
                    <!-- Les flux seront injectés ici -->
                </div>
            </div>
        </div>
    </div>
    
    <script>
    let ws;
    let pieChart, timelineChart;
    let historyData = [];
    let appsDistribution = {};
    let countdownValue = 60;
    let countdownInterval;
    let monitoredClients = [];
    let clientPanels = {};
    let clientHistory = {};
        
        // Initialiser les graphiques
        function initCharts() {
            // Pie Chart
            const pieCtx = document.getElementById('pieChart').getContext('2d');
            pieChart = new Chart(pieCtx, {
                type: 'pie',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#00d9ff', '#00ff88', '#ff6b6b', '#ffd93d',
                            '#6bcb77', '#4d96ff', '#ff9f43', '#a55eea',
                            '#26de81', '#fd79a8', '#74b9ff', '#55efc4'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { 
                                color: '#fff', 
                                font: { size: 12 },
                                padding: 15
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((context.raw / total) * 100).toFixed(1);
                                    return `${context.label}: ${context.raw} flux (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
            
            // Timeline Chart
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            timelineChart = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Flux/minute',
                        data: [],
                        borderColor: '#00d9ff',
                        backgroundColor: '#00d9ff33',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointBackgroundColor: '#00d9ff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: { 
                            ticks: { color: '#888' }, 
                            grid: { color: '#ffffff11' }
                        },
                        y: { 
                            ticks: { color: '#888' }, 
                            grid: { color: '#ffffff11' },
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        // Démarrer le countdown
        function startCountdown() {
            countdownValue = 60;
            if (countdownInterval) clearInterval(countdownInterval);
            countdownInterval = setInterval(() => {
                countdownValue--;
                document.getElementById('countdown').textContent = countdownValue;
                if (countdownValue <= 0) countdownValue = 60;
            }, 1000);
        }
        
        // Connexion WebSocket
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
            
            ws.onopen = () => {
                console.log('WebSocket connecté');
                startCountdown();
            };
            
            ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                
                if (msg.type === 'init') {
                    historyData = msg.data.history || [];
                    appsDistribution = msg.data.apps_distribution || {};
                    monitoredClients = msg.data.clients || [];
                    clientHistory = msg.data.client_history || {};
                    const statsByClient = msg.data.client_stats || {};
                    renderClientPanels(monitoredClients, statsByClient, clientHistory);
                    updateStats(msg.data.stats);
                    updateHistoryTable();
                    updatePieChart();
                    updateStatus(msg.data.running);
                    // Afficher le classement si des clients sont configurés
                    if (monitoredClients.length > 0) {
                        document.getElementById('volumeRankingSection').style.display = 'block';
                        updateVolumeRanking();
                        // Mettre à jour l'historique de chaque client
                        monitoredClients.forEach(ip => {
                            if (clientHistory[ip]) {
                                updateClientHistoryTable(ip, clientHistory[ip]);
                            }
                        });
                    }
                }
                else if (msg.type === 'minute_update') {
                    // Nouvelle entrée de minute reçue
                    historyData.push(msg.data.record);
                    if (historyData.length > 60) historyData.shift();
                    
                    appsDistribution = msg.data.apps_distribution;
                    updateStats(msg.data.stats);
                    updateHistoryTable();
                    updatePieChart();
                    updateTimelineChart();
                    
                    // Reset countdown
                    countdownValue = 60;
                }
                else if (msg.type === 'client_update') {
                    const clientIp = msg.client;
                    if (!clientHistory[clientIp]) clientHistory[clientIp] = [];
                    clientHistory[clientIp].push(msg.data.record);
                    if (clientHistory[clientIp].length > 60) {
                        clientHistory[clientIp] = clientHistory[clientIp].slice(-60);
                    }
                    updateClientPanel(clientIp, msg.data.stats, msg.data.record);
                    // Mise à jour de l'historique mini du client
                    updateClientHistoryTable(clientIp, clientHistory[clientIp]);
                    // Mise à jour du classement
                    updateVolumeRanking();
                }
                else if (msg.type === 'clients_update') {
                    monitoredClients = msg.clients || [];
                    renderClientPanels(monitoredClients, {}, {});
                    // Afficher/masquer la section classement
                    document.getElementById('volumeRankingSection').style.display = 
                        monitoredClients.length > 0 ? 'block' : 'none';
                    if (monitoredClients.length > 0) updateVolumeRanking();
                }
            };
            
            ws.onclose = () => {
                console.log('WebSocket fermé, reconnexion...');
                setTimeout(connectWebSocket, 3000);
            };
        }
        
        // Démarrer le sniffer
        async function startSniffer() {
            console.log('startSniffer appelé');
            const iface = document.getElementById('interface').value;
            const btnStart = document.getElementById('btnStart');
            const btnStop = document.getElementById('btnStop');
            
            // Désactiver le bouton pendant la requête
            btnStart.disabled = true;
            btnStart.textContent = '⏳ Démarrage...';
            
            try {
                const resp = await fetch('/api/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `interface=${iface}`
                });
                const data = await resp.json();
                console.log('Réponse:', data);
                
                if (data.success) {
                    updateStatus(true);
                } else {
                    alert('Erreur: ' + data.error);
                    btnStart.disabled = false;
                    btnStart.textContent = '▶️ Démarrer';
                }
            } catch (error) {
                console.error('Erreur fetch:', error);
                alert('Erreur de connexion au serveur: ' + error.message);
                btnStart.disabled = false;
                btnStart.textContent = '▶️ Démarrer';
            }
        }
        
        // Arrêter le sniffer
        async function stopSniffer() {
            await fetch('/api/stop', { method: 'POST' });
            updateStatus(false);
        }
        
        // Mettre à jour le statut
        function updateStatus(running) {
            const badge = document.getElementById('statusBadge');
            const btnStart = document.getElementById('btnStart');
            const btnStop = document.getElementById('btnStop');
            
            if (running) {
                badge.className = 'status-badge status-running';
                badge.textContent = '🟢 En cours...';
                btnStart.disabled = true;
                btnStop.disabled = false;
            } else {
                badge.className = 'status-badge status-stopped';
                badge.textContent = '⚫ Arrêté';
                btnStart.disabled = false;
                btnStop.disabled = true;
            }
        }
        
        // Mettre à jour les stats
        function updateStats(stats) {
            document.getElementById('totalFlows').textContent = stats.total_flows || 0;
            document.getElementById('totalVolume').textContent = (stats.volume_mb || stats.total_volume_mb || 0) + ' MB';
            document.getElementById('malwareAlerts').textContent = stats.malware_alerts || 0;
            document.getElementById('uniqueApps').textContent = Object.keys(appsDistribution).length;
        }
        
        // Mettre à jour le tableau d'historique (1 ligne par minute)
        function updateHistoryTable() {
            const tbody = document.getElementById('historyBody');
            
            if (historyData.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" class="no-data">
                            En attente de données... (mise à jour toutes les 60 secondes)
                        </td>
                    </tr>
                `;
                return;
            }
            
            // Afficher du plus récent au plus ancien
            const reversed = [...historyData].reverse();
            
            tbody.innerHTML = reversed.map(item => {
                const isMalware = item.is_malware;
                const confidence = item.confidence || 0;
                
                // Déterminer le niveau de confiance
                let confLevel = 'low';
                if (confidence >= 70) confLevel = 'high';
                else if (confidence >= 50) confLevel = 'medium';
                
                return `
                    <tr class="clickable-row ${isMalware ? 'malware' : ''}" onclick="showFlowDetails('${item.time}')" title="Cliquez pour voir les détails">
                        <td><strong>${item.time}</strong></td>
                        <td class="ip-text">${item.dest_ip}</td>
                        <td>
                            <span class="app-badge ${isMalware ? 'malware' : 'normal'}">
                                ${isMalware ? '🦠' : '📱'} ${item.app}
                            </span>
                        </td>
                        <td>
                            <span class="confidence ${confLevel}">${confidence}%</span>
                        </td>
                        <td>${item.total_flows} flux 🔍</td>
                    </tr>
                `;
            }).join('');
        }
        
        // Afficher les détails des flux dans le modal
        async function showFlowDetails(time) {
            const modal = document.getElementById('flowModal');
            const flowsList = document.getElementById('flowsList');
            
            // Afficher le modal avec état de chargement
            modal.style.display = 'flex';
            document.getElementById('modalTime').textContent = time;
            flowsList.innerHTML = '<div class="no-flows">⏳ Chargement des flux...</div>';
            
            try {
                // Récupérer les détails via l'API
                const response = await fetch(`/api/minute-details/${encodeURIComponent(time)}`);
                const data = await response.json();
                
                if (!data.success) {
                    flowsList.innerHTML = '<div class="no-flows">❌ Données non disponibles</div>';
                    return;
                }
                
                // Mettre à jour le résumé
                document.getElementById('modalTotalFlows').textContent = data.total_flows;
                document.getElementById('modalMainApp').textContent = data.dominant_app;
                document.getElementById('modalAvgConf').textContent = data.average_confidence + '%';
                
                // Afficher les flux
                if (!data.flows || data.flows.length === 0) {
                    flowsList.innerHTML = '<div class="no-flows">Aucun flux détaillé disponible</div>';
                    return;
                }
                
                flowsList.innerHTML = data.flows.map((flow, index) => {
                    // Utiliser flow.label ou flow.app en fallback
                    const appName = flow.label || flow.app || 'Inconnu';
                    const isMalware = ['ZEUS', 'TINBA', 'MIUREF', 'NERIS', 'NSIS', 'VIRUT'].includes(appName.toUpperCase());
                    let confLevel = 'low';
                    if (flow.confidence >= 70) confLevel = 'high';
                    else if (flow.confidence >= 50) confLevel = 'medium';
                    
                    return `
                        <div class="flow-item ${isMalware ? 'malware' : ''}">
                            <div class="flow-info">
                                <div class="flow-ips">
                                    📤 ${flow.src_ip || 'N/A'} → 📥 ${flow.dest_ip || 'N/A'}
                                </div>
                                <div class="flow-ports">
                                    Port: ${flow.dest_port || 'N/A'} | Protocole: ${flow.protocol || 'N/A'} | 
                                    ${flow.packets || 0} paquets | ${((flow.bytes || flow.volume || 0) / 1024).toFixed(2)} KB
                                </div>
                            </div>
                            <div class="flow-app">
                                <span class="app-badge ${isMalware ? 'malware' : 'normal'}">
                                    ${isMalware ? '🦠' : '📱'} ${appName}
                                </span>
                            </div>
                            <div class="flow-confidence">
                                <span class="confidence ${confLevel}">${flow.confidence || 0}%</span>
                            </div>
                        </div>
                    `;
                }).join('');
                
            } catch (error) {
                console.error('Erreur lors de la récupération des détails:', error);
                flowsList.innerHTML = '<div class="no-flows">❌ Erreur de connexion</div>';
            }
        }
        
        // Fermer le modal
        function closeModal(event) {
            if (event && event.target !== event.currentTarget) return;
            document.getElementById('flowModal').style.display = 'none';
        }
        
        // Fermer avec Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });
        
        // Mettre à jour le Pie Chart
        function updatePieChart() {
            if (!appsDistribution || Object.keys(appsDistribution).length === 0) return;
            
            // Trier par nombre de flux décroissant
            const sorted = Object.entries(appsDistribution)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);  // Top 10
            
            pieChart.data.labels = sorted.map(([name]) => name);
            pieChart.data.datasets[0].data = sorted.map(([, count]) => count);
            pieChart.update();
        }
        
        // Mettre à jour le Timeline Chart
        function updateTimelineChart() {
            if (historyData.length === 0) return;
            
            // Utiliser les données d'historique pour le timeline
            const recent = historyData.slice(-20);
            
            timelineChart.data.labels = recent.map(item => item.time);
            timelineChart.data.datasets[0].data = recent.map(item => item.total_flows);
            timelineChart.update();
        }
        
        // Rafraîchir les données depuis l'API
        async function refreshData() {
            try {
                const [statsResp, historyResp] = await Promise.all([
                    fetch('/api/stats'),
                    fetch('/api/history')
                ]);
                
                const stats = await statsResp.json();
                const history = await historyResp.json();
                
                appsDistribution = stats.flows_by_type || {};
                historyData = history.history || [];
                
                document.getElementById('totalFlows').textContent = stats.total_flows;
                document.getElementById('totalVolume').textContent = stats.total_volume_mb + ' MB';
                document.getElementById('malwareAlerts').textContent = stats.malware_alerts;
                document.getElementById('uniqueApps').textContent = Object.keys(appsDistribution).length;
                
                updateHistoryTable();
                updatePieChart();
                updateTimelineChart();
                
            } catch (error) {
                console.error('Erreur refresh:', error);
            }
        }
        
        // Initialisation
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            connectWebSocket();
            refreshData();
            
            // Attacher les événements aux boutons
            document.getElementById('btnStart').addEventListener('click', function(e) {
                e.preventDefault();
                console.log('Bouton Démarrer cliqué');
                startSniffer();
            });
            
            document.getElementById('btnStop').addEventListener('click', function(e) {
                e.preventDefault();
                console.log('Bouton Arrêter cliqué');
                stopSniffer();
            });

            document.getElementById('clientConfigForm').addEventListener('submit', configureClients);
            
            // Mise à jour périodique du classement
            setInterval(updateVolumeRanking, 5000);
        });

        async function configureClients(event) {
            event.preventDefault();
            const ipsInput = document.getElementById('clientIps').value;
            const ips = ipsInput.split(',').map(ip => ip.trim()).filter(Boolean);
            const statusBox = document.getElementById('configStatus');
            
            statusBox.className = 'config-status visible';
            statusBox.textContent = '⏳ Envoi de la configuration...';
            
            try {
                const resp = await fetch('/api/configure-clients', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ clients: ips })
                });
                const data = await resp.json();
                if (data.success) {
                    statusBox.className = 'config-status visible';
                    statusBox.textContent = `✅ ${data.clients.length} client(s) configuré(s): ${data.clients.join(', ')}`;
                    monitoredClients = data.clients;
                    renderClientPanels(monitoredClients, {}, {});
                    // Afficher la section de classement
                    document.getElementById('volumeRankingSection').style.display = 'block';
                    updateVolumeRanking();
                } else {
                    statusBox.className = 'config-status visible error';
                    statusBox.textContent = '❌ Erreur de configuration';
                }
            } catch (err) {
                statusBox.className = 'config-status visible error';
                statusBox.textContent = '❌ Erreur réseau: ' + err.message;
            }
        }

        async function updateVolumeRanking() {
            if (monitoredClients.length === 0) return;
            
            try {
                const resp = await fetch('/api/clients/ranking');
                const data = await resp.json();
                renderVolumeRanking(data);
            } catch (err) {
                console.error('Erreur mise à jour classement:', err);
            }
        }

        function formatVolume(bytes) {
            if (bytes >= 1024 * 1024 * 1024) {
                return { value: (bytes / (1024 * 1024 * 1024)).toFixed(2), unit: 'GB' };
            } else if (bytes >= 1024 * 1024) {
                return { value: (bytes / (1024 * 1024)).toFixed(2), unit: 'MB' };
            } else if (bytes >= 1024) {
                return { value: (bytes / 1024).toFixed(2), unit: 'KB' };
            } else {
                return { value: bytes, unit: 'B' };
            }
        }

        function formatBandwidth(mbps) {
            if (mbps >= 1000) {
                return { value: (mbps / 1000).toFixed(2), unit: 'Gbps' };
            } else if (mbps >= 1) {
                return { value: mbps.toFixed(2), unit: 'Mbps' };
            } else {
                return { value: (mbps * 1000).toFixed(1), unit: 'Kbps' };
            }
        }

        function renderVolumeRanking(data) {
            const container = document.getElementById('rankingList');
            const totalSpan = document.getElementById('rankingTotal');
            const totalBandwidthSpan = document.getElementById('rankingTotalBandwidth');
            const section = document.getElementById('volumeRankingSection');
            
            if (!data.ranking || data.ranking.length === 0) {
                container.innerHTML = '<div class="no-ranking-data">En attente de données...</div>';
                return;
            }
            
            section.style.display = 'block';
            
            // Mise à jour du total volume
            const totalFormatted = formatVolume(data.total_volume_mb * 1024 * 1024);
            totalSpan.textContent = `Total: ${totalFormatted.value} ${totalFormatted.unit}`;
            
            // Mise à jour du total bande passante
            if (totalBandwidthSpan) {
                const totalBw = formatBandwidth(data.total_bandwidth_mbps || 0);
                totalBandwidthSpan.textContent = `⚡ ${totalBw.value} ${totalBw.unit}`;
            }
            
            // Génération du classement avec débit
            container.innerHTML = data.ranking.map(client => {
                const vol = formatVolume(client.volume_bytes);
                const bw = formatBandwidth(client.bandwidth_mbps || 0);
                const rankClass = client.rank <= 3 ? `rank-${client.rank}` : '';
                const badgeClass = client.rank <= 3 ? '' : 'default';
                const medal = client.rank === 1 ? '🥇' : client.rank === 2 ? '🥈' : client.rank === 3 ? '🥉' : client.rank;
                const duration = client.session_duration_formatted || '0s';
                
                return `
                    <div class="ranking-item ${rankClass}">
                        <div class="rank-badge ${badgeClass}">${medal}</div>
                        <div class="ranking-ip">${client.ip}</div>
                        <div class="ranking-volume">
                            <span class="value">${vol.value}</span>
                            <span class="unit">${vol.unit}</span>
                        </div>
                        <div class="ranking-bandwidth">
                            <span class="value">${bw.value}</span>
                            <span class="unit">${bw.unit}</span>
                            <div class="duration">⏱️ ${duration}</div>
                        </div>
                        <div class="ranking-percent">
                            <div class="bar">
                                <div class="bar-fill" style="width: ${client.percentage}%"></div>
                            </div>
                            <span class="text">${client.percentage}%</span>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function renderClientPanels(clients, statsByClient, historyByClient) {
            const container = document.getElementById('clientPanels');
            const countBadge = document.getElementById('clientCountBadge');
            container.innerHTML = '';
            
            // Mise à jour du badge de comptage
            if (countBadge) {
                countBadge.textContent = clients && clients.length > 0 
                    ? `${clients.length} client${clients.length > 1 ? 's' : ''} configuré${clients.length > 1 ? 's' : ''}`
                    : '0 clients configurés';
            }
            
            if (!clients || clients.length === 0) {
                container.innerHTML = `
                    <div class="no-clients-message" id="noClientMessage">
                        <span>🖥️</span>
                        Configurez des clients ci-dessus pour démarrer la surveillance.
                    </div>`;
                return;
            }
            
            clients.forEach(ip => {
                const panel = document.createElement('div');
                panel.className = 'client-panel';
                panel.id = `client-panel-${ip.replace(/\./g, '-')}`;
                const safeIp = ip.replace(/\./g, '-');
                panel.innerHTML = `
                    <div class="panel-header">
                        <div>
                            <h3>🖥️ ${ip}</h3>
                            <p id="client-main-app-${ip}">App dominante: En attente...</p>
                        </div>
                        <button class="btn-secondary" onclick="openClientModal('${ip}')">📊 Détails</button>
                    </div>
                    <div class="panel-stats">
                        <div class="panel-stat">
                            <div class="label">Flux</div>
                            <div class="value" id="client-flows-${ip}">0</div>
                        </div>
                        <div class="panel-stat">
                            <div class="label">Volume</div>
                            <div class="value" id="client-volume-${ip}">0 KB</div>
                        </div>
                        <div class="panel-stat">
                            <div class="label">Confiance</div>
                            <div class="value" id="client-confidence-${ip}">0%</div>
                        </div>
                    </div>
                    <div class="mini-chart">
                        <canvas id="client-chart-${ip}"></canvas>
                    </div>
                    <div class="client-history-section">
                        <div class="client-history-header">
                            <h4>📜 Historique (1 entrée/min)</h4>
                        </div>
                        <div class="client-history-scroll">
                            <table class="mini-history-table">
                                <thead>
                                    <tr>
                                        <th>⏰</th>
                                        <th>📱 App</th>
                                        <th>📊</th>
                                        <th>📈</th>
                                    </tr>
                                </thead>
                                <tbody id="client-history-body-${safeIp}">
                                    <tr><td colspan="4" style="text-align:center;color:#666;padding:20px;">En attente...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
                container.appendChild(panel);
                // Initialiser l'historique si disponible
                if (historyByClient[ip] && historyByClient[ip].length > 0) {
                    updateClientHistoryTable(ip, historyByClient[ip]);
                }
                updateClientPanel(ip, statsByClient[ip], historyByClient[ip] ? historyByClient[ip].slice(-1)[0] : null);
            });
        }

        const clientCharts = {};

        // Fonction pour mettre à jour l'historique d'un client
        function updateClientHistoryTable(ip, history) {
            const safeIp = ip.replace(/\./g, '-');
            const tbody = document.getElementById(`client-history-body-${safeIp}`);
            if (!tbody) return;
            
            if (!history || history.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#666;padding:20px;">En attente...</td></tr>';
                return;
            }
            
            const MALWARE_APPS = ['ZEUS', 'TINBA', 'MIUREF', 'NERIS', 'NSIS', 'VIRUT'];
            
            // Afficher les 10 dernières entrées (plus récentes en haut)
            const recentHistory = history.slice(-10).reverse();
            
            tbody.innerHTML = recentHistory.map(record => {
                const app = record.app || 'UNKNOWN';
                const isMalware = MALWARE_APPS.includes(app.toUpperCase());
                const confidence = record.confidence || 0;
                const confClass = confidence >= 70 ? 'high' : confidence >= 50 ? 'medium' : 'low';
                const flowCount = record.flow_count || record.flows || 0;
                
                return `
                    <tr class="clickable-row ${isMalware ? 'malware' : ''}" 
                        onclick="showClientFlowDetails('${ip}', '${record.time}')" 
                        title="Cliquez pour voir les détails">
                        <td><strong>${record.time}</strong></td>
                        <td>
                            <span class="mini-app-badge ${isMalware ? 'malware' : 'normal'}">
                                ${isMalware ? '🦠' : '📱'} ${app}
                            </span>
                        </td>
                        <td><span class="mini-confidence ${confClass}">${confidence.toFixed(1)}%</span></td>
                        <td>${flowCount} 🔍</td>
                    </tr>
                `;
            }).join('');
        }

        // Fonction pour afficher les détails d'un flux client
        async function showClientFlowDetails(ip, minute) {
            const modal = document.getElementById('flowModal');
            modal.style.display = 'flex';
            document.getElementById('modalTime').textContent = `${ip} - ${minute}`;
            document.getElementById('flowsList').innerHTML = '<div class="no-flows">Chargement...</div>';
            
            try {
                const resp = await fetch(`/api/client/${ip}/flows/${minute}`);
                const data = await resp.json();
                renderFlowList(data.flows || []);
            } catch (err) {
                document.getElementById('flowsList').innerHTML = `<div class="no-flows">Erreur: ${err.message}</div>`;
            }
        }

        function updateClientPanel(ip, stats, latestRecord) {
            if (!stats) return;
            const flowsEl = document.getElementById(`client-flows-${ip}`);
            const volumeEl = document.getElementById(`client-volume-${ip}`);
            const confidenceEl = document.getElementById(`client-confidence-${ip}`);
            const mainAppEl = document.getElementById(`client-main-app-${ip}`);
            if (flowsEl) flowsEl.textContent = stats.total_flows || 0;
            if (volumeEl) volumeEl.textContent = (stats.volume_mb || 0) + ' MB';
            if (confidenceEl) confidenceEl.textContent = (stats.average_confidence || 0) + '%';
            if (mainAppEl && latestRecord) mainAppEl.textContent = `App dominante: ${latestRecord.app}`;

            const chartId = `client-chart-${ip}`;
            const ctx = document.getElementById(chartId);
            if (!ctx) return;
            if (!clientCharts[ip]) {
                clientCharts[ip] = new Chart(ctx, {
                    type: 'doughnut',
                    data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d9ff', '#00ff88', '#ff6b6b', '#ffd93d'] }] },
                    options: { responsive: true, plugins: { legend: { display: false } } }
                });
            }
            const chart = clientCharts[ip];
            const labels = (stats.top_apps || []).map(a => a.label);
            const data = (stats.top_apps || []).map(a => a.count);
            chart.data.labels = labels;
            chart.data.datasets[0].data = data;
            chart.update();
        }

        async function openClientModal(ip) {
            const modal = document.getElementById('flowModal');
            modal.style.display = 'flex';
            document.getElementById('modalTime').textContent = ip;
            document.getElementById('flowsList').innerHTML = '<div class="no-flows">Chargement...</div>';
            try {
                const statsResp = await fetch(`/api/client/${ip}/stats`);
                const statsData = await statsResp.json();
                const latest = statsData.latest_record;
                const flows = latest ? latest.flows_detail : [];
                document.getElementById('modalTotalFlows').textContent = latest ? latest.total_flows : 0;
                document.getElementById('modalMainApp').textContent = latest ? latest.app : '-';
                document.getElementById('modalAvgConf').textContent = statsData.stats.average_confidence + '%';
                renderFlowList(flows);
            } catch (err) {
                document.getElementById('flowsList').innerHTML = '<div class="no-flows">Erreur de chargement</div>';
            }
        }

        function renderFlowList(flows) {
            const container = document.getElementById('flowsList');
            if (!flows || flows.length === 0) {
                container.innerHTML = '<div class="no-flows">Aucun flux détaillé disponible</div>';
                return;
            }
            container.innerHTML = flows.map(flow => {
                // Utiliser flow.label (du backend) ou flow.app en fallback
                const appName = flow.label || flow.app || 'Inconnu';
                const isMalware = ['ZEUS', 'TINBA', 'MIUREF', 'NERIS', 'NSIS', 'VIRUT'].includes(appName.toUpperCase());
                let confLevel = 'low';
                if (flow.confidence >= 70) confLevel = 'high';
                else if (flow.confidence >= 50) confLevel = 'medium';
                return `
                    <div class="flow-item ${isMalware ? 'malware' : ''}">
                        <div class="flow-info">
                            <div class="flow-ips">📤 ${flow.src_ip || 'N/A'} → 📥 ${flow.dest_ip || 'N/A'}</div>
                            <div class="flow-ports">Port: ${flow.dest_port || 0} | ${flow.protocol || 'TCP'} | ${((flow.volume || 0) / 1024).toFixed(2)} KB | ${flow.packets || 0} paquets</div>
                        </div>
                        <div class="flow-app"><span class="app-badge ${isMalware ? 'malware' : 'normal'}">${appName}</span></div>
                        <div class="flow-confidence"><span class="confidence ${confLevel}">${flow.confidence || 0}%</span></div>
                    </div>
                `;
            }).join('');
        }
    </script>
</body>
</html>
"""


# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║         🔍 AI APPLICATION TRACKER - FastAPI Dashboard            ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  Ce dashboard utilise le modèle ML pour classifier le trafic     ║
    ║  réseau et identifier les applications utilisées.                ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  Prérequis:                                                      ║
    ║  • Modèle entraîné: traffic_classifier_model.joblib              ║
    ║  • Encoder: traffic_label_encoder.joblib                         ║
    ║  • Exécuter avec sudo pour le sniffing                          ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  Accès: http://localhost:8000                                    ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000)
