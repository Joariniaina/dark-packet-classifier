"""
Configuration centralisée de l'application.
Principe SOLID: Single Responsibility - Ce module gère uniquement la configuration.
"""

from dataclasses import dataclass, field
from typing import List
from pathlib import Path


@dataclass
class Settings:
    """Configuration de l'application Application Tracker."""
    
    # Chemins des modèles ML
    MODEL_FILENAME: str = 'traffic_classifier_model.joblib'
    ENCODER_FILENAME: str = 'traffic_label_encoder.joblib'
    
    # Paramètres de sniffing
    TIMEOUT_FLOW: int = 10
    CLASSIFY_PACKET_THRESHOLD: int = 10
    DEFAULT_INTERFACE: str = "wlp3s0"
    
    # Paramètres de mise à jour
    HISTORY_UPDATE_INTERVAL: int = 60  # Secondes
    MIN_CONFIDENCE_THRESHOLD: float = 0.3
    MAX_HISTORY_ENTRIES: int = 60
    
    # Features pour le modèle ML
    FEATURE_COLUMNS: List[str] = field(default_factory=lambda: [
        'duration', 'total_fiat', 'total_biat', 'min_fiat', 'min_biat',
        'max_fiat', 'max_biat', 'mean_fiat', 'mean_biat', 'flowPktsPerSecond',
        'flowBytesPerSecond', 'min_flowiat', 'max_flowiat', 'mean_flowiat',
        'std_flowiat', 'min_active', 'mean_active', 'max_active', 'std_active',
        'min_idle', 'mean_idle', 'max_idle', 'std_idle'
    ])
    
    # Liste des malwares connus
    MALWARE_LABELS: List[str] = field(default_factory=lambda: [
        'ZEUS', 'TINBA', 'MIUREF', 'NERIS', 'NSIS', 'VIRUT'
    ])
    
    # Catégories d'applications
    APP_CATEGORIES: dict = field(default_factory=lambda: {
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
    })
    
    def get_app_category(self, label: str) -> str:
        """Retourne la catégorie d'une application."""
        return self.APP_CATEGORIES.get(label, '📦 Autre')
    
    def is_malware(self, label: str) -> bool:
        """Vérifie si un label correspond à un malware."""
        clean_label = label.replace(' (?)', '')
        return clean_label in self.MALWARE_LABELS


# Instance singleton de configuration
settings = Settings()
