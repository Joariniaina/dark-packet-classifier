import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP
import time
import math
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from queue import Queue 

# --- CONFIGURATION & VARIABLES GLOBALES ---
MODEL_FILENAME = 'traffic_classifier_model.joblib'
ENCODER_FILENAME = 'traffic_label_encoder.joblib'
TIMEOUT_FLOW = 10           
CLASSIFY_PACKET_THRESHOLD = 10 

FEATURE_COLUMNS = [
    'duration', 'total_fiat', 'total_biat', 'min_fiat', 'min_biat', 
    'max_fiat', 'max_biat', 'mean_fiat', 'mean_biat', 'flowPktsPerSecond', 
    'flowBytesPerSecond', 'min_flowiat', 'max_flowiat', 'mean_flowiat', 
    'std_flowiat', 'min_active', 'mean_active', 'max_active', 'std_active', 
    'min_idle', 'mean_idle', 'max_idle', 'std_idle' 
]

local_flows = {}
model = None
label_encoder = None
gui_output = None 
result_queue = Queue() 

# Statistiques détaillées incluant le NOUVEAU suivi de la durée d'usage
stats_data = {
    'total_flows': 0,
    'malware_alerts': 0,
    'total_volume_bytes': 0,
    'volume_by_type': {},
    'volume_by_ip': {},
    'flows_by_ip': {},       
    'malware_by_ip': {},     
    'historical_data': [],  
    'usage_by_ip_dest': {} 
} 
canvas = None
ax1 = None 
ax2 = None 
ax3 = None 
root = None
total_flows_label = None
malware_alerts_label = None
total_volume_label = None
risk_table_frame = None 

all_log_messages = [] 
filter_entry = None 
usage_table_frame = None 
usage_ip_selector = None 
selected_usage_ip = None # Variable Tkinter initialisée dans setup_gui


# --------------------------------------------------------------------------
# --- COMPOSANTS ESSENTIELS DE L'EXTRACTION DE FLUX ---
# --------------------------------------------------------------------------

class FlowData:
    """Structure pour stocker l'état et les caractéristiques d'un flux."""
    def __init__(self, start_time):
        self.start_time = start_time
        self.last_time = start_time
        self.BYTES = 0      
        self.BYTES_REV = 0  
        self.PACKETS = 0    
        self.PACKETS_REV = 0 
        self.fwd_timestamps = [] 
        self.rev_timestamps = [] 
        self.last_fwd_time = 0
        self.last_rev_time = 0
        self.idle_periods = []
        self.active_times = []
        self.last_packet_time = start_time 

    def update_flow(self, packet, direction, current_time):
        """Met à jour les compteurs du flux avec un nouveau paquet."""
        length = len(packet) if IP in packet else len(packet)
        
        global TIMEOUT_FLOW
        if self.last_packet_time != self.start_time:
             idle_time = current_time - self.last_packet_time
             if idle_time > TIMEOUT_FLOW:
                 self.idle_periods.append(float(idle_time))
                 self.active_times.append(float(current_time - self.last_packet_time))
                 
        self.last_packet_time = current_time

        if direction == 'forward':
            self.BYTES += length
            self.PACKETS += 1
            if self.last_fwd_time != 0:
                self.fwd_timestamps.append(float(current_time - self.last_fwd_time))
            self.last_fwd_time = current_time
        else:
            self.BYTES_REV += length
            self.PACKETS_REV += 1
            if self.last_rev_time != 0:
                self.rev_timestamps.append(float(current_time - self.last_rev_time))
            self.last_rev_time = current_time
            
        self.last_time = current_time

    def calculate_features(self):
        """Calcule les 23 caractéristiques finales dans l'ordre."""
        
        duration = float(self.last_time - self.start_time)
        
        if self.fwd_timestamps:
            fwd_iat = np.array(self.fwd_timestamps, dtype=float)
            total_fiat, min_fiat, max_fiat, mean_fiat = np.sum(fwd_iat), np.min(fwd_iat), np.max(fwd_iat), np.mean(fwd_iat)
        else:
            total_fiat, min_fiat, max_fiat, mean_fiat = 0, 0, 0, 0

        if self.rev_timestamps:
            rev_iat = np.array(self.rev_timestamps, dtype=float)
            total_biat, min_biat, max_biat, mean_biat = np.sum(rev_iat), np.min(rev_iat), np.max(rev_iat), np.mean(rev_iat)
        else:
            total_biat, min_biat, max_biat, mean_biat = 0, 0, 0, 0

        all_timestamps = self.fwd_timestamps + self.rev_timestamps
        if all_timestamps:
            flow_iat = np.array(all_timestamps, dtype=float)
            min_flowiat, max_flowiat, mean_flowiat, std_flowiat = np.min(flow_iat), np.max(flow_iat), np.mean(flow_iat), np.std(flow_iat)
        else:
            min_flowiat, max_flowiat, mean_flowiat, std_flowiat = 0, 0, 0, 0
            
        total_packets = self.PACKETS + self.PACKETS_REV
        if duration > 0:
            flowPktsPerSecond = total_packets / duration
            flowBytesPerSecond = (self.BYTES + self.BYTES_REV) / duration
        else:
            flowPktsPerSecond, flowBytesPerSecond = 0, 0

        if self.idle_periods:
            idle_array = np.array(self.idle_periods, dtype=float)
            min_idle, mean_idle, max_idle, std_idle = np.min(idle_array), np.mean(idle_array), np.max(idle_array), np.std(idle_array)
        else:
             min_idle, mean_idle, max_idle, std_idle = 0, 0, 0, 0

        if self.active_times:
            active_array = np.array(self.active_times, dtype=float)
            min_active, mean_active, max_active, std_active = np.min(active_array), np.mean(active_array), np.max(active_array), np.std(active_array)
        else:
            min_active, mean_active, max_active, std_active = 0, 0, 0, 0
        
        feature_vector_list = [
            duration, total_fiat, total_biat, min_fiat, min_biat, 
            max_fiat, max_biat, mean_fiat, mean_biat, flowPktsPerSecond, 
            flowBytesPerSecond, min_flowiat, max_flowiat, mean_flowiat, 
            std_flowiat, min_active, mean_active, max_active, std_active, 
            min_idle, mean_idle, max_idle, std_idle
        ]
        
        return [0 if (isinstance(x, (float, np.floating)) and (math.isnan(x) or math.isinf(x))) else x for x in feature_vector_list]

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
        
        # Le flux est toujours ordonné (Client -> Serveur ou IP petite -> IP grande)
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

# --------------------------------------------------------------------------
# --- LOGIQUE D'ACTUALISATION DU TABLEAU DE BORD (GUI) ---
# --------------------------------------------------------------------------

def format_duration(seconds):
    """Convertit la durée en secondes en HH:MM:SS."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

def apply_filter(log_widget, entry_widget):
    """Applique le filtre basé sur la chaîne de recherche (IP ou Label)."""
    global all_log_messages
    
    if not entry_widget: return 

    filter_text = entry_widget.get().strip().upper()
    
    log_widget.delete(1.0, tk.END)
    
    for log_item in all_log_messages:
        message = log_item['message'].upper()
        tag = log_item['tag']
        
        if not filter_text or filter_text in message:
            log_widget.insert(tk.END, log_item['message'], tag)
            
    log_widget.tag_config('alert', foreground='red', font=('Consolas', 10, 'bold'))
    log_widget.tag_config('normal', foreground='lime green')
    log_widget.see(tk.END)


def log_alert(result):
    """Prépare l'alerte et la stocke pour le filtrage."""
    global all_log_messages
    
    message = (
        f"🚨 ALERTE MALWARE DETECTÉE : {result['label']}\n"
        f"   Client: {result['client_ip']} | Dest: {result['dest_ip']} | Durée: {result['duration']:.2f}s\n"
        "------------------------------------------------------------\n"
    )
    all_log_messages.append({'message': message, 'tag': 'alert'})
    apply_filter(gui_output, filter_entry) 

def draw_pie_chart():
    """Dessine le graphique de répartition du volume par type de trafic."""
    global ax1, canvas
    data = stats_data.get('volume_by_type', {})
    if not data: return
    total_volume = sum(data.values())
    threshold = total_volume * 0.02
    filtered_data = {k: v for k, v in data.items() if v > threshold}
    other_volume = total_volume - sum(filtered_data.values())
    if other_volume > 0:
        filtered_data['AUTRES'] = other_volume
    labels = filtered_data.keys()
    sizes = filtered_data.values()
    ax1.clear()
    ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax1.axis('equal') 
    ax1.set_title('Répartition du Volume par Type de Trafic')
    canvas.draw_idle()

def draw_bar_chart():
    """Dessine le graphique des top 5 des clients consommateurs."""
    global ax2, canvas
    data = stats_data.get('volume_by_ip', {})
    if not data: return
    sorted_data = sorted(data.items(), key=lambda item: item[1], reverse=True)[:5]
    ips = [item[0] for item in sorted_data]
    volumes = [item[1] / 1024**2 for item in sorted_data] 
    ax2.clear()
    ax2.bar(ips, volumes, color='skyblue')
    ax2.set_title('Top 5 des Clients (Volume en Mo)')
    ax2.set_ylabel('Volume (Mo)')
    ax2.tick_params(axis='x', rotation=45)
    canvas.draw_idle()

def draw_time_series_chart():
    """Dessine le graphique du débit Mo/s en fonction du temps."""
    global ax3, canvas
    data = stats_data.get('historical_data', [])
    if not data: return
    
    times = [d['time'] for d in data]
    volumes = [d['volume_rate'] for d in data]
    
    ax3.clear()
    ax3.plot(times, volumes, marker='o', linestyle='-', color='orange')
    ax3.set_title('Débit Réseau (Mo/s) vs Temps')
    ax3.set_xlabel('Temps (H:M:S)')
    ax3.set_ylabel('Débit (Mo/s)')
    step = max(1, len(times) // 5) 
    ax3.set_xticks(times[::step])
    ax3.tick_params(axis='x', rotation=45, labelsize=8)
    ax3.grid(True)
    canvas.draw_idle()

def draw_risk_table():
    """Dessine le tableau des clients actifs avec un score de risque."""
    global risk_table_frame, root
    
    if risk_table_frame:
        risk_table_frame.destroy()

    risk_table_frame = tk.Frame(root)
    risk_table_frame.pack(fill=tk.X, padx=10, pady=5)
    
    tk.Label(risk_table_frame, text="Analyse du Risque Client Actif", font=('Arial', 10, 'bold')).pack(pady=5)

    tree = ttk.Treeview(risk_table_frame, columns=('Flows', 'Alerts', 'Volume', 'RiskScore'), show='headings')
    tree.heading('#0', text='IP Client')
    tree.heading('Flows', text='Flux Total')
    tree.heading('Alerts', text='Alertes Malware')
    tree.heading('Volume', text='Volume (Mo)')
    tree.heading('RiskScore', text='Score de Risque')
    
    tree.column('#0', width=120, anchor=tk.CENTER)
    tree.column('Flows', width=70, anchor=tk.CENTER)
    tree.column('Alerts', width=100, anchor=tk.CENTER)
    tree.column('Volume', width=100, anchor=tk.CENTER)
    tree.column('RiskScore', width=100, anchor=tk.CENTER)

    client_ips = sorted(stats_data['flows_by_ip'].keys())

    for ip in client_ips:
        total_flows = stats_data['flows_by_ip'].get(ip, 0)
        malware_alerts = stats_data['malware_by_ip'].get(ip, 0)
        volume_mo = stats_data['volume_by_ip'].get(ip, 0) / 1024**2
        
        risk_score = (malware_alerts / total_flows) * 100 if total_flows > 0 else 0
        
        tag = 'high' if risk_score > 5 else 'normal' 
        if malware_alerts > 0:
            tag = 'alert' 

        tree.insert('', tk.END, text=ip, values=(
            total_flows,
            malware_alerts,
            f"{volume_mo:.2f}",
            f"{risk_score:.2f}%"
        ), tags=(tag,)) 
        
    tree.tag_configure('alert', background='red', foreground='white', font=('Arial', 9, 'bold'))
    tree.tag_configure('normal', background='white', foreground='black')

    tree.pack(fill=tk.BOTH, expand=True)
    if root:
        root.update_idletasks() # Correction: S'assurer que le tableau est bien dessiné

def draw_usage_table(*args):
    """Dessine le tableau d'utilisation par destination pour l'IP sélectionnée."""
    global usage_table_frame, selected_usage_ip, root
    
    # Vérification que selected_usage_ip est bien un StringVar
    if not isinstance(selected_usage_ip, tk.StringVar):
        return
        
    selected_ip = selected_usage_ip.get()
    
    if usage_table_frame:
        usage_table_frame.destroy()
        
    # --- CORRECTION AJOUTÉE : Force la mise à jour après destruction ---
    if root:
        root.update_idletasks() 
    # -------------------------------------------------------------------

    usage_table_frame = tk.Frame(root)
    usage_table_frame.pack(fill=tk.X, padx=10, pady=5)
    
    tk.Label(usage_table_frame, text=f"Durée d'Utilisation par Destination pour {selected_ip}", font=('Arial', 10, 'bold')).pack(pady=5)

    tree = ttk.Treeview(usage_table_frame, columns=('Duration'), show='headings')
    tree.heading('#0', text='Destination IP')
    tree.heading('Duration', text='Durée Totale')
    
    tree.column('#0', width=150, anchor=tk.W)
    tree.column('Duration', width=100, anchor=tk.CENTER)

    # Remplissage du tableau
    usage_data = stats_data['usage_by_ip_dest'].get(selected_ip, {})
    
    # Trier par durée (la plus longue en premier)
    sorted_usage = sorted(usage_data.items(), key=lambda item: item[1], reverse=True)[:10]

    for dest_ip, duration in sorted_usage:
        formatted_duration = format_duration(duration)
        tree.insert('', tk.END, text=dest_ip, values=(
            formatted_duration,
        ))
        
    if not sorted_usage and selected_ip != "N/A":
        tree.insert('', tk.END, text="Pas de données d'usage pour cette IP.", values=(''))

    tree.pack(fill=tk.BOTH, expand=True)
    
    # --- CORRECTION AJOUTÉE : Force la mise à jour après création ---
    if root:
        root.update_idletasks()
    # -------------------------------------------------------------------


def update_dashboard():
    """Traite les résultats de la queue, met à jour les stats et redessine les graphiques."""
    global root, stats_data, total_volume_label, total_flows_label, malware_alerts_label, all_log_messages, gui_output, filter_entry
    global usage_ip_selector, selected_usage_ip
    
    new_results = 0
    current_batch_volume = 0 

    # 1. Traitement des nouveaux résultats de la queue
    while not result_queue.empty():
        result = result_queue.get()
        new_results += 1
        
        # Mise à jour des stats de base et pour le Risk Score
        stats_data['total_flows'] += 1
        stats_data['total_volume_bytes'] += result['volume']
        current_batch_volume += result['volume'] 
        stats_data['volume_by_type'][result['label']] = stats_data['volume_by_type'].get(result['label'], 0) + result['volume']
        stats_data['volume_by_ip'][result['client_ip']] = stats_data['volume_by_ip'].get(result['client_ip'], 0) + result['volume']
        stats_data['flows_by_ip'][result['client_ip']] = stats_data['flows_by_ip'].get(result['client_ip'], 0) + 1 
        
        # Mise à jour du suivi de l'usage par destination
        client_ip = result['client_ip']
        dest_ip = result['dest_ip']
        duration = result['duration']
        
        if client_ip not in stats_data['usage_by_ip_dest']:
            stats_data['usage_by_ip_dest'][client_ip] = {}
        
        stats_data['usage_by_ip_dest'][client_ip][dest_ip] = stats_data['usage_by_ip_dest'][client_ip].get(dest_ip, 0) + duration

        # Alerte/Log
        if result['label'] in ['ZEUS', 'TINBA', 'MIUREF']:
            stats_data['malware_alerts'] += 1
            stats_data['malware_by_ip'][result['client_ip']] = stats_data['malware_by_ip'].get(result['client_ip'], 0) + 1 
            log_alert(result) 
        else:
             message = f"Flow classé : {result['label']} | {result['client_ip']} -> {result['dest_ip']} | Durée: {duration:.2f}s\n"
             all_log_messages.append({'message': message, 'tag': 'normal'})
             
    # 2. Mise à jour des historiques et KPIs
    current_time_label = time.strftime('%H:%M:%S')
    volume_mo_per_sec = (current_batch_volume / (1024**2)) / 5.0 
    stats_data['historical_data'].append({'time': current_time_label, 'volume_rate': volume_mo_per_sec})
    stats_data['historical_data'] = stats_data['historical_data'][-30:] 

    if total_flows_label: 
        total_flows_label.config(text=f"Total Flux Classifiés: {stats_data['total_flows']}")
        malware_alerts_label.config(text=f"Alertes Malwares: {stats_data['malware_alerts']}")
        total_volume_label.config(text=f"Volume Total: {(stats_data['total_volume_bytes']/1024**3):.2f} Go")

    # 3. Mise à jour des graphiques et des tableaux
    if new_results > 0 or stats_data['total_flows'] == 0:
        try:
            draw_pie_chart()
            draw_bar_chart()
            draw_time_series_chart()
            draw_risk_table()
            
            # Mise à jour du sélecteur d'IP
            current_ips = sorted(stats_data['flows_by_ip'].keys())
            if usage_ip_selector:
                current_selection = selected_usage_ip.get()
                
                if current_ips:
                    usage_ip_selector['values'] = current_ips
                    # Si aucune IP n'est sélectionnée, prendre la première
                    if current_selection not in current_ips or current_selection == "N/A":
                        selected_usage_ip.set(current_ips[0])
                else:
                    usage_ip_selector['values'] = ["N/A"]
                    selected_usage_ip.set("N/A")

            # Mise à jour du tableau d'usage (Doit être appelé ici pour rafraîchir les durées)
            draw_usage_table()
            
            if new_results > 0:
                apply_filter(gui_output, filter_entry) 
        except Exception as e:
            if gui_output:
                root.after(0, lambda: [
                    gui_output.insert(tk.END, f"\nERREUR D'AFFICHAGE GRAPHIQUE/TABLEAU: {e}\n", 'error'),
                    gui_output.tag_config('error', foreground='red')
                ])
        
    if root:
        root.after(5000, update_dashboard) 

# --------------------------------------------------------------------------
# --- LOGIQUE DU SNIFFER ET DE CLASSIFICATION ---
# --------------------------------------------------------------------------

def classify_and_enqueue(flow_data, flow_key, client_ip, dest_ip): 
    """Calcule les caractéristiques et place le résultat dans la queue."""
    global model, label_encoder, result_queue

    feature_vector_list = flow_data.calculate_features()
    X_predict = pd.DataFrame([feature_vector_list], columns=FEATURE_COLUMNS)
    X_predict = X_predict.replace([np.inf, -np.inf], np.nan).fillna(0) 

    try:
        prediction_encoded = model.predict(X_predict)[0]
        prediction_label = label_encoder.inverse_transform([prediction_encoded])[0]
    except Exception:
        prediction_label = "INCONNU" 

    volume_bytes = flow_data.BYTES + flow_data.BYTES_REV
    duration = flow_data.last_time - flow_data.start_time

    result_queue.put({
        'label': prediction_label,
        'volume': volume_bytes,
        'client_ip': client_ip,
        'dest_ip': dest_ip,     
        'key': flow_key,
        'duration': duration
    })

def process_packet(packet):
    """Logique de Scapy pour traiter chaque paquet."""
    global local_flows, CLASSIFY_PACKET_THRESHOLD
    
    quintuple, direction, client_ip, dest_ip = get_flow_quintuple(packet)
    if not quintuple:
        return
        
    flow_key = quintuple
    current_time = packet.time 
    
    if flow_key not in local_flows:
        local_flows[flow_key] = FlowData(start_time=current_time)
        
    flow = local_flows[flow_key]
    flow.update_flow(packet, direction, current_time=current_time)

    if flow_key[4] == 6 and TCP in packet and (packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04): 
        classify_and_enqueue(flow, flow_key, client_ip, dest_ip)
        del local_flows[flow_key]
        return

    if (flow.PACKETS + flow.PACKETS_REV) >= CLASSIFY_PACKET_THRESHOLD:
        classify_and_enqueue(flow, flow_key, client_ip, dest_ip)
        del local_flows[flow_key]
        return
        
def clean_and_classify_flows():
    """Vérifie et classifie les flux expirés (par timeout)."""
    global local_flows, root
    
    flows_to_classify = []
    current_time = time.time()
    
    for key, flow in local_flows.items():
        if current_time - flow.last_time > TIMEOUT_FLOW: 
            flows_to_classify.append((key, flow))

    for key, flow in flows_to_classify:
        if key in local_flows:
            # Les IPs sont stockées dans la clé (quintuple)
            client_ip = key[0] 
            dest_ip = key[2] 
                 
            classify_and_enqueue(local_flows[key], key, client_ip, dest_ip)
            del local_flows[key]
        
    if root:
        threading.Timer(1.0, clean_and_classify_flows).start()

# Fonction cible du thread de sniffing
def sniffer_thread_func(interface):
    """Fonction exécutée dans un thread pour démarrer le sniffing."""
    global gui_output, root
    try:
        # Lancement de la capture de paquets
        sniff(iface=interface, prn=process_packet, store=0) 
    except Exception as e:
        # Afficher l'erreur dans la GUI (en utilisant root.after car c'est un thread secondaire)
        if gui_output and root:
             root.after(0, lambda: gui_output.insert(tk.END, f"\nERREUR FATALE DE SNIFFING sur {interface}: {e}\n", 'error'))
             gui_output.tag_config('error', foreground='red')

def start_sniffing(interface):
    """Démarre le thread de sniffing et charge le modèle."""
    global model, label_encoder, gui_output, root

    if not interface or not interface.strip():
        gui_output.insert(tk.END, "\nERREUR: Veuillez spécifier une interface réseau.\n", 'error')
        gui_output.tag_config('error', foreground='red')
        return

    try:
        # 1. Chargement des fichiers
        if model is None:
            model = joblib.load(MODEL_FILENAME)
            label_encoder = joblib.load(ENCODER_FILENAME)
        
        gui_output.insert(tk.END, "Modèle et Encoder chargés : Prêt pour la prédiction.\n")
        gui_output.insert(tk.END, f"Démarrage de l'écoute sur l'interface {interface}...\n\n")

        # 2. Démarrage du nettoyeur de flux
        threading.Timer(1.0, clean_and_classify_flows).start()

        # 3. Démarrage du sniffer dans un thread
        sniffer_thread = threading.Thread(target=sniffer_thread_func, args=(interface,))
        sniffer_thread.daemon = True 
        sniffer_thread.start()

    except FileNotFoundError:
        gui_output.insert(tk.END, "\nERREUR: Fichiers modèle ou encoder introuvables. Lancez train_classifier.py d'abord.\n", 'error')
        gui_output.tag_config('error', foreground='red')
    except Exception as e:
        gui_output.insert(tk.END, f"\nERREUR de chargement : {e}\n", 'error')
        gui_output.tag_config('error', foreground='red')


# --------------------------------------------------------------------------
# --- GESTION DE LA GUI ---
# --------------------------------------------------------------------------

def setup_gui():
    global gui_output, canvas, ax1, ax2, ax3, root, total_volume_label, malware_alerts_label, total_flows_label, filter_entry, usage_ip_selector, selected_usage_ip
    
    root = tk.Tk()
    root.title("Tableau de Bord de Surveillance du Trafic Réseau (IA)")

    # Initialisation de la variable Tkinter après la création du root
    selected_usage_ip = tk.StringVar(root)
    selected_usage_ip.set("N/A")

    # 1. Zone de Contrôle et KPIs (Haut)
    top_frame = tk.Frame(root, pady=10)
    top_frame.pack(fill=tk.X)
    
    # --- CONTRÔLES D'INTERFACE ET DÉMARRAGE ---
    control_frame = tk.Frame(top_frame)
    control_frame.pack(side=tk.LEFT, padx=10)
    
    tk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
    interface_entry = tk.Entry(control_frame, width=15)
    interface_entry.insert(0, "wlp0s20f3") 
    interface_entry.pack(side=tk.LEFT, padx=5)
    
    start_button = tk.Button(control_frame, text="Démarrer la Surveillance", fg="white", bg="darkgreen", 
                             command=lambda: [start_sniffing(interface_entry.get()), start_button.config(state=tk.DISABLED)])
    start_button.pack(side=tk.LEFT, padx=10)
    # --- FIN CONTRÔLES D'INTERFACE ---

    # --- INDICATEURS CLÉS DE PERFORMANCE (KPIs) ---
    kpi_frame = tk.Frame(top_frame)
    kpi_frame.pack(side=tk.RIGHT, padx=10)
    
    total_flows_label = tk.Label(kpi_frame, text="Total Flux Classifiés: 0", font=('Arial', 10, 'bold'))
    total_flows_label.pack(side=tk.LEFT, padx=10)
    
    malware_alerts_label = tk.Label(kpi_frame, text="Alertes Malwares: 0", fg="red", font=('Arial', 10, 'bold'))
    malware_alerts_label.pack(side=tk.LEFT, padx=10)
    
    total_volume_label = tk.Label(kpi_frame, text="Volume Total: 0.00 Go", font=('Arial', 10, 'bold'))
    total_volume_label.pack(side=tk.LEFT, padx=10)
    # --- FIN KPIs ---


    # 2. Zone des Graphiques (Milieu)
    plot_frame = tk.Frame(root)
    plot_frame.pack(fill=tk.BOTH, expand=True)

    fig = Figure(figsize=(12, 6), dpi=100)
    ax1 = fig.add_subplot(131)  
    ax2 = fig.add_subplot(132)  
    ax3 = fig.add_subplot(133)  
    fig.tight_layout(pad=2.0) 

    canvas = FigureCanvasTkAgg(fig, master=plot_frame)
    canvas_widget = canvas.get_tk_widget()
    canvas_widget.pack(fill=tk.BOTH, expand=True)

    # 3. Tableau d'Analyse du Risque (Affiché par draw_risk_table)
    
    # --- NOUVELLE ZONE 4: TABLEAU D'USAGE (Top Destinations) ---
    usage_control_frame = tk.Frame(root)
    usage_control_frame.pack(fill=tk.X, padx=10, pady=5)
    
    tk.Label(usage_control_frame, text="Analyser l'Usage de l'IP :").pack(side=tk.LEFT, padx=5)
    
    usage_ip_selector = ttk.Combobox(usage_control_frame, textvariable=selected_usage_ip, state="readonly", width=15)
    usage_ip_selector.pack(side=tk.LEFT, padx=5)
    # Liaison de la fonction de dessin au changement de sélection
    usage_ip_selector.bind("<<ComboboxSelected>>", draw_usage_table) 
    # --- FIN TABLEAU D'USAGE ---

    # 5. Zone de Log des Alertes et Filtrage (Bas)
    log_label = tk.Label(root, text="Journal des Alertes et Activités:")
    log_label.pack(pady=5)

    filter_frame = tk.Frame(root)
    filter_frame.pack(padx=10, pady=2, fill=tk.X)
    
    tk.Label(filter_frame, text="Rechercher (IP, Malware, etc.):").pack(side=tk.LEFT)
    
    filter_entry = tk.Entry(filter_frame, width=30)
    filter_entry.pack(side=tk.LEFT, padx=5)
    
    filter_button = tk.Button(filter_frame, text="Filtrer", 
                              command=lambda: apply_filter(gui_output, filter_entry))
    filter_button.pack(side=tk.LEFT)

    output_frame = tk.Frame(root)
    output_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
    
    gui_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=100, height=8, font=("Consolas", 10), bg="black", fg="lime green")
    gui_output.pack(fill=tk.BOTH, expand=True)
    
    # Démarrage de la boucle de rafraîchissement
    root.after(100, update_dashboard)
    
    root.mainloop()

if __name__ == "__main__":
    setup_gui()