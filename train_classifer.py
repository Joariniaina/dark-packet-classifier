import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib 
import numpy as np

# --- CONFIGURATION ---
DATASET_PATH = 'ustc_extracted_features.csv' 
MODEL_FILENAME = 'traffic_classifier_model.joblib'
ENCODER_FILENAME = 'traffic_label_encoder.joblib'

# Liste des caractéristiques (23 colonnes utilisées)
FEATURE_COLUMNS = [
    'duration', 'total_fiat', 'total_biat', 'min_fiat', 'min_biat', 
    'max_fiat', 'max_biat', 'mean_fiat', 'mean_biat', 'flowPktsPerSecond', 
    'flowBytesPerSecond', 'min_flowiat', 'max_flowiat', 'mean_flowiat', 
    'std_flowiat', 'min_active', 'mean_active', 'max_active', 'std_active', 
    'min_idle', 'mean_idle', 'max_idle', 'std_idle' 
]


def train_and_save_model():
    """Charge les données, entraîne le modèle, affiche les metrics et le sauvegarde."""
    try:
        print(f"1. Chargement du dataset depuis {DATASET_PATH}...")
        df = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"ERREUR : Le fichier {DATASET_PATH} est introuvable. Veuillez vérifier le chemin.")
        return

    # --- PRÉ-TRAITEMENT ---
    
    try:
        X = df[FEATURE_COLUMNS]
        y = df['traffic_type']
    except KeyError as e:
        print(f"ERREUR: La colonne {e} est introuvable. Veuillez ajuster FEATURE_COLUMNS ou vérifier le nom de la colonne cible ('traffic_type').")
        return
        
    # Gérer les valeurs infinies ou NaN (pour éviter les warnings)
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.mean())

    # 2. Encoder la Cible (y)
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Sauvegarder l'encoder
    joblib.dump(label_encoder, ENCODER_FILENAME)

    # 3. Entraînement du Modèle
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42)
    
    print(f"Taille de l'ensemble d'entraînement: {len(X_train)} échantillons.")
    print("Démarrage de l'entraînement du classifieur Random Forest...")
    
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, max_depth=50, min_samples_split= 2)
    model.fit(X_train, y_train)

    # 4. Évaluation (Ajout de l'accuracy d'entraînement)
    
    # Accuracy sur l'ensemble d'ENTRAÎNEMENT
    train_accuracy = model.score(X_train, y_train)
    # Accuracy sur l'ensemble de TEST
    test_accuracy = model.score(X_test, y_test)
    
    print("\n--- RÉSULTATS D'ÉVALUATION ---")
    print(f"🎯 Précision du modèle sur l'ensemble d'entraînement: {train_accuracy*100:.2f}%")
    print(f"✅ Précision du modèle sur l'ensemble de test: {test_accuracy*100:.2f}%")
    print("--------------------------------")

    # 5. Sauvegarde
    joblib.dump(model, MODEL_FILENAME)
    print(f"\n✅ Modèle entraîné et sauvegardé sous {MODEL_FILENAME}.")
    print(f"✅ Encoder de labels sauvegardé sous {ENCODER_FILENAME}.")

if __name__ == "__main__":
    train_and_save_model()