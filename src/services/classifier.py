"""
ClassifierService - Service de classification ML.
Principe SOLID: 
- Single Responsibility: Gère uniquement la classification ML
- Open/Closed: Peut être étendu pour d'autres modèles
- Dependency Inversion: Interface abstraite pour le modèle
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import joblib
from datetime import datetime

from ..config import settings
from ..models.flow import FlowData


class IClassifier(ABC):
    """Interface abstraite pour les classifiers (Dependency Inversion)."""
    
    @abstractmethod
    def predict(self, features: List[float]) -> Tuple[str, float, Dict[str, float]]:
        """Prédit la classe à partir des features."""
        pass
    
    @abstractmethod
    def is_loaded(self) -> bool:
        """Vérifie si le modèle est chargé."""
        pass


class ClassifierService(IClassifier):
    """Service de classification du trafic réseau."""
    
    def __init__(self, model_path: str = None, encoder_path: str = None):
        """
        Initialise le service de classification.
        
        Args:
            model_path: Chemin vers le modèle .joblib
            encoder_path: Chemin vers l'encodeur .joblib
        """
        self.model_path = model_path or settings.MODEL_FILENAME
        self.encoder_path = encoder_path or settings.ENCODER_FILENAME
        self.model = None
        self.label_encoder = None
        self._loaded = False
    
    def load(self) -> bool:
        """Charge le modèle et l'encodeur."""
        try:
            print("📦 Chargement du modèle ML...")
            self.model = joblib.load(self.model_path)
            self.label_encoder = joblib.load(self.encoder_path)
            self._loaded = True
            print("✅ Modèle chargé avec succès!")
            print(f"   Classes: {list(self.label_encoder.classes_)}")
            return True
        except FileNotFoundError as e:
            print(f"❌ ERREUR: Modèle non trouvé! {e}")
            print("   Exécutez d'abord train_classifer.py")
            self._loaded = False
            return False
        except Exception as e:
            print(f"❌ ERREUR lors du chargement: {e}")
            self._loaded = False
            return False
    
    def is_loaded(self) -> bool:
        """Vérifie si le modèle est chargé."""
        return self._loaded and self.model is not None
    
    def predict(self, features: List[float]) -> Tuple[str, float, Dict[str, float]]:
        """
        Prédit la classe à partir d'un vecteur de features.
        
        Args:
            features: Vecteur de 23 features
            
        Returns:
            Tuple (label, confidence, all_probabilities)
        """
        if not self.is_loaded():
            return "UNKNOWN", 0.0, {}
        
        try:
            # Créer le DataFrame avec les features
            X_predict = pd.DataFrame([features], columns=settings.FEATURE_COLUMNS)
            X_predict = X_predict.replace([np.inf, -np.inf], np.nan).fillna(0)
            
            # Obtenir les probabilités
            probabilities = self.model.predict_proba(X_predict)[0]
            classes = self.label_encoder.classes_
            
            # Créer le dictionnaire de toutes les probabilités
            all_probabilities = {
                cls: round(float(prob) * 100, 2) 
                for cls, prob in zip(classes, probabilities)
            }
            
            # Trouver la classe avec la plus haute probabilité
            max_prob_idx = np.argmax(probabilities)
            confidence = float(probabilities[max_prob_idx]) * 100
            prediction_label = classes[max_prob_idx]
            
            # Si la confiance est trop basse, marquer comme incertain
            if confidence < settings.MIN_CONFIDENCE_THRESHOLD * 100:
                prediction_label = f"{prediction_label} (?)"
            
            return prediction_label, round(confidence, 1), all_probabilities
            
        except Exception as e:
            print(f"❌ Erreur de classification: {e}")
            return "UNKNOWN", 0.0, {}
    
    def classify_flow(self, flow_data: FlowData, flow_key: tuple, 
                     client_ip: str, dest_ip: str, 
                     monitored_clients: List[str] = None) -> dict:
        """
        Classifie un flux complet et retourne le résultat formaté.
        
        Args:
            flow_data: Données du flux
            flow_key: Clé du flux (quintuple)
            client_ip: IP source
            dest_ip: IP destination
            monitored_clients: Liste des clients surveillés dans ce flux
            
        Returns:
            Dictionnaire du résultat de classification
        """
        # Calculer les features
        features = flow_data.calculate_features()
        
        # Classifier
        label, confidence, all_probs = self.predict(features)
        
        # Déterminer le niveau de confiance
        if confidence >= 80:
            confidence_level = "high"
        elif confidence >= 50:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        
        # Vérifier si c'est un malware
        is_malware = settings.is_malware(label)
        
        return {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'label': label,
            'confidence': confidence,
            'confidence_level': confidence_level,
            'all_probabilities': all_probs,
            'volume': flow_data.total_bytes,
            'client_ip': client_ip,
            'dest_ip': dest_ip,
            'dest_port': flow_key[3],
            'protocol': 'TCP' if flow_key[4] == 6 else 'UDP',
            'duration': round(flow_data.duration, 2),
            'packets': flow_data.total_packets,
            'is_malware': is_malware,
            'monitored_clients': monitored_clients or []
        }
    
    @property
    def classes(self) -> List[str]:
        """Retourne la liste des classes du modèle."""
        if self.label_encoder is not None:
            return list(self.label_encoder.classes_)
        return []
