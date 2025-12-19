#  DarkPacketClassifier

**Système Intelligent de Classification du Trafic Réseau par Machine Learning**

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.95-green.svg)
![Scapy](https://img.shields.io/badge/Scapy-2.5.0-red.svg)
![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest-orange.svg)

##  Présentation
Le **DarkPacketClassifier** est une solution de cybersécurité permettant d'identifier en temps réel les applications et les menaces au sein d'un flux réseau, même si celui-ci est chiffré (HTTPS, TLS, VPN). 

Contrairement aux solutions classiques de DPI (*Deep Packet Inspection*), cet outil utilise une **approche comportementale non-invasive** : il analyse la "silhouette" temporelle et volumétrique du trafic plutôt que le contenu des messages.



---

##  Fonctionnalités Clés
* **Capture Passive (Sniffing) :** Interception des paquets via Raw Sockets et interface en mode *Promiscuous*.
* **Analyse de Trafic Chiffré :** Identification des applications sans déchiffrement.
* **Détection de Malwares :** Reconnaissance des signatures comportementales (ex: Zeus, Virut).
* **Dashboard Temps Réel :** Interface interactive utilisant des **WebSockets** pour une mise à jour fluide des statistiques.
* **Architecture SOLID :** Code structuré pour une maintenance et une scalabilité maximales.

---

##  Architecture du Projet (Clean Architecture)
Le projet est organisé pour séparer strictement les responsabilités :

* **`src/api/`** : Gestion des routes FastAPI et de la communication temps réel (WebSockets).
* **`src/services/`** : Logique métier (Sniffer pour le réseau, Classifier pour l'IA).
* **`src/models/`** : Définition des structures de données (FlowData).
* **`data/`** : Stockage du modèle pré-entraîné (`.joblib`).

---

##  Pipeline de Machine Learning

### 1. Dataset & Entraînement
Le modèle a été entraîné sur le dataset de référence **CIC-IDS2017**, enrichi par des captures réelles.
* **Classes :** 11 catégories (YouTube, Spotify, VoIP, DNS, Malware Zeus, etc.).
* **Algorithme :** Random Forest Classifier.

### 2. Feature Engineering (Extraction de Caractéristiques)
L'IA analyse **23 caractéristiques statistiques** extraites de chaque flux :
* **IAT (Inter-Arrival Time) :** Analyse des délais entre les paquets (Moyenne, Écart-type, Max/Min). C'est le "rythme cardiaque" de l'application.
* **Flow 5-Tuple :** Agrégation par IP Source/Dest, Port Source/Dest et Protocole.
* **Volume :** Statistiques sur la taille des segments (Forward/Backward).



### 3. Performances du Modèle
| Métrique | Score |
| :--- | :--- |
| **Précision (Accuracy)** | **95.2%** |
| **Fiabilité (Precision)** | 94.1% |
| **Rappel (Recall)** | 93.5% |



---

##  Installation et Lancement

### Prérequis
* Python 3.9+
* Privilèges `sudo` (requis pour l'accès aux interfaces réseau brutes)

### Installation
```bash``

 ### Utilisation
 sudo python main.py
cd dark-packet-classifier
pip install -r requirements.txt  
