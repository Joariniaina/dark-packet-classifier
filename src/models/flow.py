"""
FlowData Model - Extraction des features réseau.
Principe SOLID: Single Responsibility - Gère uniquement l'état et le calcul des features d'un flux.
"""

import math
import numpy as np
from dataclasses import dataclass, field
from typing import List
from scapy.all import IP


@dataclass
class FlowData:
    """Structure pour stocker l'état et les caractéristiques d'un flux réseau."""
    
    start_time: float
    last_time: float = field(init=False)
    
    # Compteurs de bytes et paquets
    BYTES: int = 0
    BYTES_REV: int = 0
    PACKETS: int = 0
    PACKETS_REV: int = 0
    
    # Timestamps pour IAT
    fwd_timestamps: List[float] = field(default_factory=list)
    rev_timestamps: List[float] = field(default_factory=list)
    all_packet_times: List[float] = field(default_factory=list)
    
    last_fwd_time: float = 0
    last_rev_time: float = 0
    
    # Périodes d'activité/inactivité
    idle_periods: List[float] = field(default_factory=list)
    active_periods: List[float] = field(default_factory=list)
    last_packet_time: float = field(init=False)
    current_active_start: float = field(init=False)
    
    # Seuil pour idle
    IDLE_THRESHOLD: float = 1.0
    
    def __post_init__(self):
        """Initialise les champs calculés après __init__."""
        self.last_time = self.start_time
        self.last_packet_time = self.start_time
        self.current_active_start = self.start_time
    
    def update_flow(self, packet, direction: str, current_time: float) -> None:
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
            self._update_forward(length, current_time)
        else:
            self._update_reverse(length, current_time)
            
        self.last_time = current_time
    
    def _update_forward(self, length: int, current_time: float) -> None:
        """Met à jour les métriques forward."""
        self.BYTES += length
        self.PACKETS += 1
        if self.last_fwd_time != 0:
            fwd_iat = current_time - self.last_fwd_time
            if fwd_iat > 0:
                self.fwd_timestamps.append(float(fwd_iat))
        self.last_fwd_time = current_time
    
    def _update_reverse(self, length: int, current_time: float) -> None:
        """Met à jour les métriques reverse."""
        self.BYTES_REV += length
        self.PACKETS_REV += 1
        if self.last_rev_time != 0:
            rev_iat = current_time - self.last_rev_time
            if rev_iat > 0:
                self.rev_timestamps.append(float(rev_iat))
        self.last_rev_time = current_time
    
    def calculate_features(self) -> List[float]:
        """Calcule les 23 caractéristiques finales dans l'ordre."""
        # Duration
        duration = max(0.0, float(self.last_time - self.start_time))
        
        # Forward IAT features
        total_fiat, min_fiat, max_fiat, mean_fiat = self._calc_iat_stats(self.fwd_timestamps)
        
        # Backward IAT features
        total_biat, min_biat, max_biat, mean_biat = self._calc_iat_stats(self.rev_timestamps)
        
        # Flow IAT features
        min_flowiat, max_flowiat, mean_flowiat, std_flowiat = self._calc_flow_iat_stats()
        
        # Packets and Bytes per second
        total_packets = self.PACKETS + self.PACKETS_REV
        total_bytes = self.BYTES + self.BYTES_REV
        if duration > 0:
            flowPktsPerSecond = float(total_packets / duration)
            flowBytesPerSecond = float(total_bytes / duration)
        else:
            flowPktsPerSecond = float(total_packets)
            flowBytesPerSecond = float(total_bytes)

        # Active time features
        min_active, mean_active, max_active, std_active = self._calc_active_stats(duration)
        
        # Idle time features
        min_idle, mean_idle, max_idle, std_idle = self._calc_idle_stats()
        
        # Construire le vecteur de features dans l'ordre exact
        feature_vector = [
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
        return self._clean_features(feature_vector)
    
    def _calc_iat_stats(self, timestamps: List[float]) -> tuple:
        """Calcule les statistiques IAT (total, min, max, mean)."""
        if len(timestamps) > 0:
            iat = np.array(timestamps, dtype=np.float64)
            return (
                float(np.sum(iat)),
                float(np.min(iat)),
                float(np.max(iat)),
                float(np.mean(iat))
            )
        return 0.0, 0.0, 0.0, 0.0
    
    def _calc_flow_iat_stats(self) -> tuple:
        """Calcule les statistiques Flow IAT (min, max, mean, std)."""
        if len(self.all_packet_times) > 1:
            sorted_times = sorted(self.all_packet_times)
            flow_iats = [sorted_times[i+1] - sorted_times[i] 
                        for i in range(len(sorted_times)-1)]
            flow_iats = [iat for iat in flow_iats if iat > 0]
            
            if len(flow_iats) > 0:
                flow_iat = np.array(flow_iats, dtype=np.float64)
                return (
                    float(np.min(flow_iat)),
                    float(np.max(flow_iat)),
                    float(np.mean(flow_iat)),
                    float(np.std(flow_iat)) if len(flow_iat) > 1 else 0.0
                )
        return 0.0, 0.0, 0.0, 0.0
    
    def _calc_active_stats(self, duration: float) -> tuple:
        """Calcule les statistiques des périodes actives."""
        active_list = self.active_periods.copy()
        final_active = self.last_time - self.current_active_start
        if final_active > 0:
            active_list.append(float(final_active))
            
        if len(active_list) > 0:
            active_array = np.array(active_list, dtype=np.float64)
            return (
                float(np.min(active_array)),
                float(np.mean(active_array)),
                float(np.max(active_array)),
                float(np.std(active_array)) if len(active_array) > 1 else 0.0
            )
        return duration, duration, duration, 0.0
    
    def _calc_idle_stats(self) -> tuple:
        """Calcule les statistiques des périodes idle."""
        if len(self.idle_periods) > 0:
            idle_array = np.array(self.idle_periods, dtype=np.float64)
            return (
                float(np.min(idle_array)),
                float(np.mean(idle_array)),
                float(np.max(idle_array)),
                float(np.std(idle_array)) if len(idle_array) > 1 else 0.0
            )
        return 0.0, 0.0, 0.0, 0.0
    
    @staticmethod
    def _clean_features(features: List[float]) -> List[float]:
        """Nettoie les valeurs NaN et Inf du vecteur de features."""
        cleaned = []
        for x in features:
            if isinstance(x, (float, np.floating)):
                if math.isnan(x) or math.isinf(x):
                    cleaned.append(0.0)
                else:
                    cleaned.append(float(x))
            else:
                cleaned.append(float(x))
        return cleaned
    
    @property
    def total_bytes(self) -> int:
        """Retourne le volume total du flux."""
        return self.BYTES + self.BYTES_REV
    
    @property
    def total_packets(self) -> int:
        """Retourne le nombre total de paquets."""
        return self.PACKETS + self.PACKETS_REV
    
    @property
    def duration(self) -> float:
        """Retourne la durée du flux."""
        return self.last_time - self.start_time
