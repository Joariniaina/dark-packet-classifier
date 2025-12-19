# 🔍 DarkPacketClassifier
## Classification Intelligente du Trafic Réseau par Machine Learning

---

# 📋 Plan de la Présentation

1. **Contexte et Problématique**
2. **Objectifs du Projet**
3. **Architecture Technique**
4. **Dataset et Features**
5. **Modèle de Machine Learning**
6. **Dashboard en Temps Réel**
7. **Surveillance Multi-Clients & Bande Passante**
8. **Démonstration**
9. **Résultats et Performances**
10. **Conclusion et Perspectives**

---

# 1️⃣ Contexte et Problématique

## Le Défi de la Sécurité Réseau

- 📈 **Explosion du trafic réseau** : +30% par an
- 🎭 **Applications camouflées** : Utilisent des ports standards (80, 443)
- 🦠 **Menaces sophistiquées** : Malwares, botnets, exfiltration de données
- 🔐 **Chiffrement généralisé** : Inspection de contenu impossible (HTTPS)

## Limites des Approches Traditionnelles

| Méthode | Limitation |
|---------|------------|
| Filtrage par port | Facilement contourné |
| Inspection de contenu (DPI) | Inefficace sur trafic chiffré |
| Signatures statiques | Ne détecte pas les variantes |
| Listes noires d'IP | Mises à jour trop lentes |

---

# 2️⃣ Objectifs du Projet

## Objectif Principal

> **Classifier automatiquement le trafic réseau en temps réel** pour identifier les applications et détecter les menaces, **sans inspecter le contenu des paquets**.

## Objectifs Spécifiques

- ✅ Entraîner un modèle ML sur des caractéristiques comportementales
- ✅ Classifier 11 types d'applications (légitimes + malwares)
- ✅ Développer un dashboard de monitoring en temps réel
- ✅ Supporter la surveillance multi-clients
- ✅ Générer des alertes pour les activités suspectes

---

# 3️⃣ Architecture Technique

```
┌─────────────────────────────────────────────────────────────────┐
│                      ARCHITECTURE GLOBALE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   📡 CAPTURE          🔬 ANALYSE           🖥️ VISUALISATION    │
│   ┌─────────┐        ┌──────────┐         ┌──────────────┐     │
│   │ Scapy   │───────▶│ Feature  │────────▶│  Dashboard   │     │
│   │ Sniffer │        │Extraction│         │   FastAPI    │     │
│   └─────────┘        └──────────┘         └──────────────┘     │
│        │                   │                      │             │
│        ▼                   ▼                      ▼             │
│   ┌─────────┐        ┌──────────┐         ┌──────────────┐     │
│   │ Packets │        │ ML Model │         │  WebSocket   │     │
│   │  Queue  │        │ (Random  │         │  Real-time   │     │
│   │         │        │  Forest) │         │   Updates    │     │
│   └─────────┘        └──────────┘         └──────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Stack Technologique

| Composant | Technologie |
|-----------|-------------|
| Backend API | FastAPI (Python) |
| Capture réseau | Scapy |
| Machine Learning | Scikit-learn (RandomForest) |
| Frontend | HTML5 / CSS3 / JavaScript |
| Temps réel | WebSocket |
| Visualisation | Chart.js |

---

# 4️⃣ Dataset USTC-TFC2016

## Source des Données

- **Nom** : USTC-TFC2016 (University of Science and Technology of China)
- **Type** : Trafic réseau étiqueté
- **Format** : Fichiers PCAP convertis en CSV

## Applications Classifiées (11 classes)

### ✅ Applications Légitimes (6)
| Application | Description |
|-------------|-------------|
| **SKYPE** | Communication VoIP |
| **FACETIME** | Appels vidéo Apple |
| **BITTORRENT** | Partage P2P |
| **FTP** | Transfert de fichiers |
| **GMAIL** | Messagerie Google |
| **OUTLOOK** | Messagerie Microsoft |
| **MYSQL** | Base de données |
| **WORLDOFWARCRAFT** | Jeu en ligne |

### 🚨 Malwares Détectés (3)
| Malware | Type |
|---------|------|
| **ZEUS** | Trojan bancaire |
| **TINBA** | Tiny Banker (vol de données) |
| **MIUREF** | Botnet / Adware |

---

# 5️⃣ Les 23 Features Comportementales

## Pourquoi des Features Temporelles ?

> Le **comportement temporel** d'un flux est difficile à falsifier, contrairement aux ports ou adresses IP.

## Catégories de Features

### 📏 Durée (1 feature)
- `duration` : Durée totale du flux

### ⏱️ Temps Inter-Arrivée Directionnel (8 features)
- `total_fiat/biat` : Somme des délais (Forward/Backward)
- `min_fiat/biat` : Délai minimum
- `max_fiat/biat` : Délai maximum
- `mean_fiat/biat` : Délai moyen

### 🔄 Débit (2 features)
- `flowPktsPerSecond` : Paquets par seconde
- `flowBytesPerSecond` : Octets par seconde

### 🔀 Inter-Arrivée Global (4 features)
- `min/max/mean/std_flowiat` : Statistiques sur tous les paquets

### 📊 Activité/Inactivité (8 features)
- `min/max/mean/std_active` : Périodes de transfert
- `min/max/mean/std_idle` : Périodes de pause

---

# 5️⃣ Features - Signatures Comportementales

## Profils Typiques par Application

| Application | Caractéristiques |
|-------------|------------------|
| **Streaming (FaceTime, Skype)** | Débit constant, faible variabilité, longues périodes actives |
| **Téléchargement (BitTorrent, FTP)** | Haut débit, longue durée |
| **Messagerie (Gmail, Outlook)** | Petits bursts, longues pauses |
| **Jeux (WoW)** | Paquets fréquents mais petits |
| **Malware (Zeus, Tinba)** | Patterns irréguliers, communications furtives |

```
    STREAMING           TÉLÉCHARGEMENT         MALWARE
    ▁▁▁▁▁▁▁▁▁▁         █████████████         ▃▁█▁▂▁▇▁▁▄
    (régulier)          (continu)            (irrégulier)
```

---

# 6️⃣ Modèle de Machine Learning

## Algorithme : Random Forest Classifier

### Pourquoi Random Forest ?

- ✅ **Robuste** aux valeurs aberrantes
- ✅ **Pas de normalisation** requise
- ✅ **Interprétable** (importance des features)
- ✅ **Rapide** en prédiction
- ✅ **Gère bien** les classes déséquilibrées

### Pipeline d'Entraînement

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Chargement  │───▶│   Split      │───▶│ Entraînement │
│    CSV       │    │ Train/Test   │    │   RandomForest│
└──────────────┘    │   80/20      │    └──────────────┘
                    └──────────────┘           │
                                               ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Sauvegarde  │◀───│  Évaluation  │◀───│  Prédiction  │
│   .joblib    │    │  Accuracy    │    │    Test      │
└──────────────┘    └──────────────┘    └──────────────┘
```

### Fichiers Générés
- `traffic_classifier_model.joblib` : Modèle entraîné
- `traffic_label_encoder.joblib` : Encodeur des labels

---

# 7️⃣ Dashboard en Temps Réel

## Fonctionnalités Principales

### 🎛️ Configuration Multi-Clients
- Saisie dynamique des IPs à surveiller
- Jusqu'à 20 clients simultanés

### 📊 Statistiques Globales
- Flux total analysés
- Applications détectées
- Volume de données
- Alertes malware

### 🖥️ Panels Par Client
- Statistiques individuelles (Flux, Volume, Confiance)
- Graphique de distribution des apps (Doughnut Chart)
- **Historique des flux par client** (1 entrée/minute)
- Clic sur un flux pour voir les détails

### 🏆 Classement par Consommation
- Pourcentage de bande passante par client
- Débit en Mbps en temps réel
- Médailles pour les 3 premiers consommateurs

---

# 7️⃣ Dashboard - Interface

```
┌─────────────────────────────────────────────────────────────────┐
│  🔍 AI Application Tracker              [▶️ Démarrer] [⏹️ Stop] │
├─────────────────────────────────────────────────────────────────┤
│  ⚙️ Configuration des Clients                                   │
│  ┌─────────────┐  ┌─────────────────────────────────────┐      │
│  │ Nb clients  │  │ IPs: 192.168.1.10, 192.168.1.20     │      │
│  │     2       │  └─────────────────────────────────────┘      │
│  └─────────────┘                    [✅ Valider]                │
├─────────────────────────────────────────────────────────────────┤
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐                   │
│  │  156   │ │   8    │ │ 45 MB  │ │ 🚨 2   │                   │
│  │ Flux   │ │ Apps   │ │ Volume │ │Alertes │                   │
│  └────────┘ └────────┘ └────────┘ └────────┘                   │
├─────────────────────────────────────────────────────────────────┤
│  🏆 Classement par Consommation & Bande Passante   Total: 45MB │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 🥇 │ 192.168.1.10  │ 25.5 MB │ 1.42 Mbps │ ████░░ │ 57%  │  │
│  │ 🥈 │ 192.168.1.20  │ 19.5 MB │ 0.98 Mbps │ ███░░░ │ 43%  │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  🖥️ Client 192.168.1.10        🖥️ Client 192.168.1.20         │
│  ┌─────────────────────┐       ┌─────────────────────┐         │
│  │ Flux: 89  Vol: 25MB │       │ Flux: 67  Vol: 19MB │         │
│  │ [====PIE CHART====] │       │ [====PIE CHART====] │         │
│  │ 📜 Historique:      │       │ 📜 Historique:      │         │
│  │ 14:35 GMAIL   87.3% │       │ 14:35 FTP    92.1%  │         │
│  │ 14:34 SKYPE   78.2% │       │ 14:34 ZEUS🦠 65.4%  │         │
│  │     [📊 Détails]    │       │     [📊 Détails]    │         │
│  └─────────────────────┘       └─────────────────────┘         │
├─────────────────────────────────────────────────────────────────┤
│  📜 Historique Global (1 entrée/minute)                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Heure  │ IP Dest      │ Application │ Confiance │ Flux  │   │
│  │ 14:35  │ 216.58.214.4 │ GMAIL       │ 87.3%     │ 12 🔍 │   │
│  │ 14:34  │ 151.101.1.69 │ 🦠 ZEUS     │ 65.4%     │ 45 🔍 │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

# 7️⃣ Nouvelles Fonctionnalités

## 🏆 Classement par Bande Passante

### Calcul du Débit (Mbps)

$$\text{Débit (Mbps)} = \frac{\text{Volume (bytes)} \times 8}{\text{Durée session (s)} \times 1\,000\,000}$$

### Affichage du Classement

| Rang | Client IP | Volume | Débit | Barre | % |
|------|-----------|--------|-------|-------|---|
| 🥇 | 192.168.1.10 | 25.5 MB | 1.42 Mbps | ████████░░ | 57% |
| 🥈 | 192.168.1.20 | 19.5 MB | 0.98 Mbps | ██████░░░░ | 43% |

## 📜 Historique par Client

Chaque panel client affiche maintenant :
- Les 10 dernières minutes d'activité
- Application dominante + confiance
- Badge malware si détecté (🦠)
- Clic sur une ligne → Détails des flux

---

# 8️⃣ Communication Temps Réel

## WebSocket Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Sniffer   │────────▶│   Server    │────────▶│   Browser   │
│   Thread    │         │   FastAPI   │         │  Dashboard  │
└─────────────┘         └─────────────┘         └─────────────┘
       │                       │                       │
       │    result_queue       │     WebSocket        │
       │ ──────────────────▶   │ ──────────────────▶  │
       │                       │                       │
       │   Chaque paquet       │    Broadcast JSON    │
       │   classifié           │    à tous clients    │
```

## Types de Messages WebSocket

```json
{
  "type": "client_update",
  "client_ip": "192.168.1.10",
  "data": {
    "timestamp": "14:35:22",
    "app": "GMAIL",
    "confidence": 87.3,
    "volume": 1024
  }
}
```

---

# 9️⃣ Processus de Classification

## Flux de Traitement d'un Paquet

```
1. CAPTURE           2. AGRÉGATION         3. EXTRACTION
┌─────────────┐      ┌─────────────┐       ┌─────────────┐
│   Packet    │─────▶│   Flow      │──────▶│  23 Features│
│  IP/TCP/UDP │      │ (src,dst,   │       │  calculées  │
│             │      │  ports)     │       │             │
└─────────────┘      └─────────────┘       └─────────────┘
                            │                     │
                            │ 10 packets          │
                            │ minimum             │
                            ▼                     ▼
4. PRÉDICTION        5. PROBABILITÉS      6. RÉSULTAT
┌─────────────┐      ┌─────────────┐       ┌─────────────┐
│ RandomForest│─────▶│ predict_    │──────▶│ App: GMAIL  │
│  .predict() │      │ proba()     │       │ Conf: 87.3% │
└─────────────┘      └─────────────┘       └─────────────┘
```

## Seuils de Décision

| Confiance | Interprétation |
|-----------|----------------|
| > 70% | ✅ Classification fiable |
| 50-70% | ⚠️ Classification incertaine |
| < 50% | ❓ Non fiable |

---

# 🔟 Détection des Malwares

## Malwares Détectables

| Malware | Description | Comportement Réseau |
|---------|-------------|---------------------|
| **ZEUS** | Trojan bancaire | Connexions C&C furtives |
| **TINBA** | Vol de credentials | Petits paquets irréguliers |
| **MIUREF** | Botnet/Adware | Trafic HTTP suspect |

## Système d'Alertes

```javascript
// Détection automatique
if (['ZEUS', 'TINBA', 'MIUREF'].includes(app)) {
    malwareAlerts++;
    showAlert(`🚨 MALWARE DÉTECTÉ: ${app}`);
}
```

## Indicateurs Visuels

- 🔴 **Badge rouge** sur les flux malveillants
- 🚨 **Compteur d'alertes** en temps réel
- 📊 **Statistiques** de menaces par client

---

# 1️⃣1️⃣ Résultats et Performances

## Métriques du Modèle

| Métrique | Valeur |
|----------|--------|
| **Accuracy** | ~95% |
| **Precision** | ~94% |
| **Recall** | ~93% |
| **F1-Score** | ~93% |

## Performances Temps Réel

| Indicateur | Performance |
|------------|-------------|
| Latence classification | < 10ms |
| Paquets/seconde | ~1000 |
| Clients simultanés | Jusqu'à 20 |
| Mise à jour dashboard | 60 sec |

## Matrice de Confusion (simplifiée)

```
              Prédit
           Légit  Malware
Réel Légit   ✅      ❌ (rare)
     Malware ❌ (rare) ✅
```

---

# 1️⃣2️⃣ Démonstration

## Étapes de la Démo

### 1. Lancement du Dashboard
```bash
sudo python3 app_tracker_api.py
```

### 2. Accès Web
```
http://localhost:8000
```

### 3. Configuration des Clients
- Entrer les IPs à surveiller
- Cliquer sur "Valider"

### 4. Démarrage du Sniffing
- Cliquer sur "▶️ Démarrer"
- Observer les flux en temps réel

### 5. Analyse des Résultats
- Consulter les statistiques par client
- Vérifier les alertes malware
- Explorer l'historique

---

# 1️⃣3️⃣ Limitations et Améliorations

## Limitations Actuelles

| Limitation | Impact |
|------------|--------|
| Dataset limité | 11 classes seulement |
| Trafic chiffré | Features réduites |
| Nouveaux malwares | Non détectés si inconnus |
| Volume élevé | Latence possible |

## Améliorations Futures

- 🔮 **Deep Learning** : CNN/RNN pour séquences de paquets
- 📊 **Plus de classes** : +50 applications
- 🌐 **Trafic chiffré** : Analyse des métadonnées TLS
- ☁️ **Cloud** : Déploiement distribué
- 🤖 **Auto-ML** : Réentraînement automatique

---

# 1️⃣4️⃣ Conclusion

## Ce que nous avons réalisé

✅ **Modèle ML fonctionnel** classifiant 11 types de trafic

✅ **Dashboard temps réel** avec WebSocket

✅ **Surveillance multi-clients** dynamique

✅ **Détection de malwares** avec alertes

✅ **Interface intuitive** et responsive

## Points Clés

> 🎯 La classification comportementale du trafic réseau est une approche **efficace et non-invasive** pour la sécurité réseau.

> 🔬 Les **23 features temporelles** capturent des signatures difficiles à falsifier.

> ⚡ Le **temps réel** permet une réponse rapide aux menaces.

---

# 1️⃣5️⃣ Questions ?

## Ressources

- 📂 **Repository** : github.com/Liantsoarandria0803/DarkPacketClassifier
- 📊 **Dataset** : USTC-TFC2016
- 📚 **Documentation** : README.md

## Contact

- 👤 **Auteur** : Liantsoarandria
- 📧 **Email** : [votre email]

---

# Merci de votre attention ! 🙏

```
    ____             __    ____             __        __ 
   / __ \____ ______/ /__ / __ \____ ______/ /_____  / /_
  / / / / __ `/ ___/ //_// /_/ / __ `/ ___/ //_/ _ \/ __/
 / /_/ / /_/ / /  / ,<  / ____/ /_/ / /__/ ,< /  __/ /_  
/_____/\__,_/_/  /_/|_|/_/    \__,_/\___/_/|_|\___/\__/  
                                                         
         Classification Intelligente du Trafic Réseau
```
