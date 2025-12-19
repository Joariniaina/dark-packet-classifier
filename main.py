"""
DarkPacketClassifier - Application Principale Refactorisée
Architecture SOLID avec injection de dépendances.
"""

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
from pathlib import Path

# Import des services
from src.config import settings
from src.services import ClassifierService, SnifferService, StatsService, WebSocketManager
from src.api import clients_router, stats_router, sniffer_router, websocket_router
from src.api.clients import init_router as init_clients_router
from src.api.stats import init_router as init_stats_router
from src.api.sniffer import init_router as init_sniffer_router
from src.api.websocket import init_router as init_websocket_router


# ============================================================================
# SERVICES GLOBAUX (Dependency Injection Container)
# ============================================================================

classifier_service = ClassifierService()
stats_service = StatsService()
sniffer_service = SnifferService(classifier_service)
ws_manager = WebSocketManager()


# ============================================================================
# BOUCLES ASYNCHRONES
# ============================================================================

async def process_results_loop():
    """Traite les résultats de classification et les agrège dans le buffer de la minute."""
    while True:
        while not sniffer_service.result_queue.empty():
            result = sniffer_service.result_queue.get()
            stats_service.process_result(result)
        await asyncio.sleep(0.5)


async def broadcast_history_loop():
    """Toutes les 60 secondes, crée un enregistrement d'historique avec l'app dominante."""
    while True:
        await asyncio.sleep(settings.HISTORY_UPDATE_INTERVAL)
        
        # Finaliser la minute globale
        minute_data = stats_service.finalize_minute()
        if minute_data:
            await ws_manager.broadcast({
                'type': 'minute_update',
                'data': minute_data
            })
        
        # Finaliser les minutes des clients
        client_data = stats_service.finalize_client_minutes()
        for client_ip, payload in client_data.items():
            await ws_manager.broadcast({
                'type': 'client_update',
                'client': client_ip,
                'data': payload
            })


# ============================================================================
# CYCLE DE VIE DE L'APPLICATION
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application."""
    
    # Startup
    classifier_service.load()
    
    # Initialiser les routers avec les services (Dependency Injection)
    init_clients_router(stats_service, sniffer_service, ws_manager)
    init_stats_router(stats_service)
    init_sniffer_router(sniffer_service)
    init_websocket_router(ws_manager, stats_service, sniffer_service)
    
    # Démarrer les tâches asynchrones
    asyncio.create_task(process_results_loop())
    asyncio.create_task(broadcast_history_loop())
    
    yield
    
    # Shutdown
    sniffer_service.stop()
    print("👋 Arrêt de l'application...")


# ============================================================================
# APPLICATION FASTAPI
# ============================================================================

app = FastAPI(
    title="🔍 DarkPacketClassifier", 
    description="Classification intelligente du trafic réseau par Machine Learning",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclure les routers (Interface Segregation)
app.include_router(clients_router)
app.include_router(stats_router)
app.include_router(sniffer_router)
app.include_router(websocket_router)


# ============================================================================
# ROUTE PRINCIPALE - DASHBOARD
# ============================================================================

def load_template() -> str:
    """Charge le template HTML depuis le fichier."""
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    if template_path.exists():
        return template_path.read_text(encoding='utf-8')
    else:
        # Fallback: template minimal
        return """
        <!DOCTYPE html>
        <html>
        <head><title>DarkPacketClassifier</title></head>
        <body>
            <h1>Template non trouvé</h1>
            <p>Le fichier templates/dashboard.html n'existe pas.</p>
        </body>
        </html>
        """


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Page principale du dashboard."""
    return HTMLResponse(content=load_template())


# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║     🔍 DARKPACKETCLASSIFIER - Architecture SOLID v2.0            ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  Ce dashboard utilise le modèle ML pour classifier le trafic     ║
    ║  réseau et identifier les applications utilisées.                ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  Architecture:                                                   ║
    ║  • src/config/     - Configuration centralisée                   ║
    ║  • src/models/     - Modèles de données (FlowData, Stats)       ║
    ║  • src/services/   - Services métier (Classifier, Sniffer)      ║
    ║  • src/api/        - Routes API séparées par domaine            ║
    ║  • templates/      - Templates HTML                              ║
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
