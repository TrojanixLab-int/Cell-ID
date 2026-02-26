import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import math
import re

class AdvancedCellAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Mobilfunkzellen-Analyzer - M. Trojan")
        self.root.geometry("1300x750")
        self.root.configure(bg="#2c3e50")

        self.default_config = {"port": "", "profile": 0}
        self.load_settings()

        self.ser = None
        self.last_cid = None
        self.current_max_dbm = -999
        self.cell_start_time = None
        self.history_data = []
        self.neighbor_cells = {}
        self.start_ts = "--:--:--"
        self.is_vertical = False
        self.imei = "--"
        self.hersteller = "--"
        self.modell = "--"
        self.revision = "--"
        self.cmd_profiles = [
            (b'AT+EINFO\r', "Allgemein Mobile"),
            (b'AT+COPS=3,0;+COPS?\r', "Dell"),
            (b'AT+SURSERV\r', "Ericsson"),
            (b'AT^SMONI\r', "Gemalto"),
            (b'AT^HCSQ?\r', "Huawei"),
            (b'AT+XREG?\r', "Intel (PC/Apple)"),
            (b'AT+EMSRV?\r', "MediaTek (Android)"),
            (b'AT+NUESTATS\r', "Neul/HiSilicon"),
            (b'AT$QCRSRP\r', "Qualcomm (Android)"),
            (b'AT+QENG="servingcell"\r', "Quectel"),
            (b'AT+MODEMINFO\r', "Samsung"),
            (b'AT!GSTATUS?\r', "Sierra"),
            (b'AT+CPSI?\r', "SimCom"),
            (b'AT#RFSTS\r', "Telit"),
            (b'AT+UCEDATA?\r', "u-blox"),
            (b'AT+ZCELLINFO?\r', "ZTE")
        ]
        self.current_profile_idx = self.saved_profile if hasattr(self, 'saved_profile') else 0
        
        self.running = True
        
        self.debug_streaming = False
        
        #Liste der Netzbetreiber (Stand: 02-2026)
        self.mnc_dict = {
            "01": "Telekom DE", "06": "Telekom DE", 
            "02": "Vodafone DE", "04": "Vodafone DE", "09": "Vodafone DE", 
            "03": "Telefónica DE", "05": "O2 Telefónica DE", #ehemals E-Plus
            "07": "Telefónica DE", "08": "O2 Telefónica DE", "11": "Telefónica DE", #ehemals O2
            "10": "DBInfraGo AG", "60": "DBInfraGo AG", "13": "BAAINBw", 
            "14": "Lebara Limited", "15": "Airdata", "22": "sipgate Wireless", 
            "23": "1&1 Mobilfunk", "43": "Lycamobile", "72": "Ericsson", "74": "Ericsson", 
            "73": "Nokia", "78": "T-Mobile", "98": "nicht-öffentlich",
        }
        
        self.bands = [
            (0, 124, "900 MHz P-GSM"), (512, 885, "1800 MHz GSM"),
            (975, 1023, "900 MHz E-GSM"), (10562, 10838, "2100 MHz UMTS"),
            (0, 599, "2100 MHz UMTS"), (1200, 1949, "1800 MHz LTE-3"),
            (2400, 2649, "2600 MHz LTE-7"), (3450, 3799, "900 MHz LTE-8"),
            (6150, 6449, "800 MHz LTE-20"), (9210, 9659, "700 MHz LTE 5G"),
            (3257, 4458, "950 MHz UMTS"), (2937, 3088, "900 MHz UMTS 3G"),
        ]

        self.setup_gui()
        
    def save_settings(self):
        try:
            with open("config.txt", "w") as f:
                port = self.port_combo.get() 
                profile = self.current_profile_idx 
                orientation = "1" if self.is_vertical else "0"
                f.write(f"{port}\n{profile}\n{orientation}")
        except:
            pass

    def load_settings(self):
        try:
            with open("config.txt", "r") as f:
                lines = f.readlines()
                if len(lines) >= 2:
                    self.saved_port = lines[0].strip()
                    self.saved_profile = int(lines[1].strip())
                else:
                    self.saved_port = ""
                    self.saved_profile = 0
                    
                if len(lines) >= 3:
                    self.saved_orientation = lines[2].strip() == "1"
                else:
                    self.saved_orientation = False
        except:
            self.saved_port = ""
            self.saved_profile = 0
            self.saved_orientation = False
            
    def on_closing(self):
        self.save_settings()
        self.running = False
        if self.ser:
            self.ser.close()
        self.root.destroy()
        
    def get_full_freq_info(self, chan):
        if (0 <= chan <= 124) or (975 <= chan <= 1023):
            if 0 <= chan <= 124:
                f_down = 935.0 + (0.2 * chan)
            else:
                f_down = 925.2 + (0.2 * (chan - 975))
            f_up = f_down - 45.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 512 <= chan <= 885:
            f_down = 1805.2 + (0.2 * (chan - 512))
            f_up = f_down - 95.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 10562 <= chan <= 10838:
            f_down = chan / 5.0
            f_up = f_down - 190.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 2937 <= chan <= 3088:
            f_down = chan / 5.0
            f_up = f_down - 45.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 6150 <= chan <= 6449:
            f_down = 791.0 + (0.1 * (chan - 6150))
            f_up = f_down - 30.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 1200 <= chan <= 1949:
            f_down = 1805.0 + (0.1 * (chan - 1200))
            f_up = f_down - 95.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 2400 <= chan <= 2649:
            f_down = 2620.0 + (0.1 * (chan - 2400))
            f_up = f_down - 120.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 3450 <= chan <= 3799:
            f_down = 925.0 + (0.1 * (chan - 3450))
            f_up = f_down - 45.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        elif 9210 <= chan <= 9659:
            f_down = 758.0 + (0.1 * (chan - 9210))
            f_up = f_down - 55.0
            return f"↓ {f_down:.1f} MHz | ↑ {f_up:.1f} MHz"
        return f"Ch: {chan}"
        
    def show_info(self):
        info_text = """Dieses Programm wird als nicht-kommerzielle Freeware zur Verfügung gestellt. Andere Nutzungen sind unter unten genannten Bedingungen erwerbbar.

BEDIENUNGSANLEITUNG

(C) 2026 - Cell-ID: Mobilfunkzellen-Analyzer von  M. Trojan - Trojanix Lab int.

Programmbeschreibung und Kompatibilität
Die Software dient der technischen Analyse von Mobilfunkzellen und wird über eine grafische Benutzeroberfläche gesteuert. Das Programm ist für den Betrieb mit Mobilfunkmodems konzipiert (z. B. Ericsson, Dell, Huawei, Sierra, Telit, Quectel, Gemalto). Die Kompatibilität umfasst im PC verbaute Module sowie über USB verbundene Endgeräte wie Handys oder Tablets, sofern diese einen seriellen Kommunikationsanschluss zur Verfügung stellen.

Ermittlung des COM-Ports
Die Identifikation des Kommunikationsanschlusses erfolgt manuell über das Betriebssystem:

    PC (Windows): Im Geräte-Manager wird unter „Anschlüsse (COM & LPT)“ die Portnummer des Modems ermittelt.
    Handy/Tablet: Das Endgerät muss im Modem- oder Diagnosemodus verbunden sein, um als COM-Port gelistet zu werden.
    Im Programm: Der Port wird über das Dropdown-Menü gewählt. Die Liste basiert auf den beim Programmstart verfügbaren Systemressourcen. Der richtige COM-Port ist in der Regel gewählt, wenn nach Verbinden eine ICCID angezeigt wird.

Bedienoberfläche und Funktionen

    Verbinden: Initiiert der serielle Kommunikation mit dem gewählten Port und Profil, dieses wird nach beenden gespeichert.
    Ansicht wechseln: Schaltet das GUI-Layout zwischen einer vertikalen und einer horizontalen Darstellung um, dieses wird auch nach beenden gespeichert.
    Echtzeit-Anzeige: Visualisiert Technologie, Kanal (ARFCN/EARFCN), PCI, Signalstärke (RSSI) sowie Netzwerkparameter (MCC, MNC, LAC, CID) der aktiven Zelle.
    Zellhistorie: Protokolliert chronologisch alle Zellwechsel mit Kanalnummer und Maximalpegel.
    Reichweiten-Tabelle: Listet alle identifizierbaren Zellen in der Umgebung auf. Die aktive Verbindung wird türkisfarben hervorgehoben, Nachbarzellen werden in Grau dargestellt.

Funktionen der Schaltfläche „Raw/Diag.“
Diese Schaltfläche öffnet das erweiterte Analyse-Terminal zur direkten Interaktion mit der Hardware:

    Live-Log: Zeigt den ungefilterten Datenaustausch zwischen Software und Modem.
    Manuelle Befehlseingabe: Über die Eingabezeile können spezifische AT-Befehle manuell gesendet werden, um Antworten jenseits der Automatik zu provozieren.
    DEBUG (Hersteller-Support-Check): Diese Funktion dient der Identifikation des Befehlssatzes. Es wird eine umfassende Liste herstellerspezifischer Diagnosebefehle (u.a. für Qualcomm, Intel, MediaTek, HiSilicon) abgearbeitet. Das Programm prüft bei jedem Befehl, ob dieser von der angeschlossenen Hardware unterstützt wird („SUPPORTED“) oder nicht („not supported“). Dies ermöglicht es dem Anwender, exakt zu bestimmen, welche erweiterten Diagnosedaten das vorliegende Modem liefern kann.
    Log-Verwaltung: Ermöglicht das Leeren des Textbereichs oder das Kopieren des gesamten Scan-Ergebnisses zur Dokumentation.

CREDITS & RECHTLICHE HINWEISE

Entwickler: Mehmet S. Trojan - Trojanix Lab int., Copyright 2026

Lizenz: Dieses Programm wird als Freeware zur Verfügung gestellt. Die Nutzung ist ausschließlich auf den privaten Bereich beschränkt. Eine kommerzielle Nutzung ist erst nach Entrichtung einer entsprechenden Gebühr gestattet. Konditionen und Abwicklung unter: m-trojan@mail.ru

Haftungsausschluss:
Die Nutzung der Software erfolgt ausdrücklich auf eigene Gefahr. Der Entwickler übernimmt keinerlei Haftung für direkte oder indirekte Schäden, die durch eine unsachgemäße Behandlung des Programms oder der verwendeten Hardware (PC, Modem, Mobilfunkendgeräte) entstehen. Dies gilt insbesondere für Fehlfunktionen oder Hardwaredefekte, die durch die manuelle Eingabe von Steuerbefehlen über das Diagnose-Terminal hervorgerufen werden könnten. Ein Anspruch auf Schadersatz bei Datenverlust oder Folgeschäden am Betriebssystem oder der Hardware ist ausgeschlossen."""
        messagebox.showinfo("Information", info_text)

    def setup_gui(self):
        top_frame = tk.Frame(self.root, bg="#34495e", pady=10)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.btn_debug = tk.Button(top_frame, text="Raw/Diag.", command=self.show_debug_window, bg="#e67e22", fg="white", font=("Arial", 10, "bold"))
        self.btn_debug.pack(side=tk.LEFT, padx=5)
        
        self.btn_view = tk.Button(top_frame, text="Ansicht (H/V)", command=self.toggle_view, bg="black", fg="white", width=12, font=("Arial", 10, "bold"))
        self.btn_view.pack(side=tk.LEFT, padx=5)

        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo = ttk.Combobox(top_frame, values=ports, width=15)
        self.port_combo.pack(side=tk.LEFT, padx=5)
        
        if hasattr(self, 'saved_port') and self.saved_port in ports:
            self.port_combo.set(self.saved_port)

        self.btn_connect = tk.Button(top_frame, text="START", command=self.toggle_connection, bg="#27ae60", fg="white", width=10, font=("Arial", 10, "bold"))
        self.btn_connect.pack(side=tk.LEFT, padx=5)

        self.btn_reset = tk.Button(top_frame, text="RESET", command=self.reset_logs, bg="#7f8c8d", fg="white", width=10, font=("Arial", 10, "bold"))
        self.btn_reset.pack(side=tk.LEFT, padx=5)

        self.btn_copy = tk.Button(top_frame, text="KOPIEREN", command=self.copy_history, bg="#2980b9", fg="white", width=10, font=("Arial", 10, "bold"))
        self.btn_copy.pack(side=tk.LEFT, padx=5)
        
        self.btn_profile = tk.Button(top_frame, text="Profil wechseln", command=self.switch_profile, bg="#8e44ad", fg="white", width=15, font=("Arial", 10, "bold"))
        self.btn_profile.pack(side=tk.LEFT, padx=5)

        if hasattr(self, 'saved_profile'):
            self.current_profile_idx = self.saved_profile
            cmd, name = self.cmd_profiles[self.current_profile_idx]
            self.lbl_profile_name = tk.Label(top_frame, text=f"Profil: {name}", bg="#34495e", fg="#f1c40f", font=("Arial", 10, "bold"))
        else:
            self.lbl_profile_name = tk.Label(top_frame, text="Profil: Allgemein Mobile", bg="#34495e", fg="#f1c40f", font=("Arial", 10, "bold"))
        
        self.lbl_profile_name.pack(side=tk.LEFT, padx=10)

        self.btn_info = tk.Button(top_frame, text="Infos", command=self.show_info, bg="#7f8c8d", fg="white", width=10, font=("Arial", 10, "bold"))
        self.btn_info.pack(side=tk.RIGHT, padx=5)

        info_main = tk.Frame(self.root, bg="#ecf0f1", relief=tk.RIDGE, bd=2)
        info_main.pack(fill=tk.X, padx=10, pady=5)
        for i in range(4): info_main.columnconfigure(i, weight=1)

        self.canvas = tk.Canvas(info_main, width=220, height=160, bg="#ecf0f1", highlightthickness=0)
        self.canvas.grid(row=0, column=0, padx=10, pady=10)

        stats_f = tk.Frame(info_main, bg="#ecf0f1")
        stats_f.grid(row=0, column=1, sticky="nw", pady=20)

        self.lbl_status = tk.Label(stats_f, text="Status: --", font=("Courier", 14), bg="#ecf0f1")
        self.lbl_status.pack(anchor="w")

        self.lbl_dbm = tk.Label(stats_f, text="Signal: -- dBm", font=("Courier", 15), bg="#ecf0f1")
        self.lbl_dbm.pack(anchor="w")
        self.lbl_cid_top = tk.Label(stats_f, text="Cell-ID: --", font=("Courier", 18, "bold"), fg="#2980b9", bg="#ecf0f1")
        self.lbl_cid_top.pack(anchor="w", pady=5)
        self.lbl_lac_top = tk.Label(stats_f, text="LAC: --", font=("Courier", 14), bg="#ecf0f1")
        self.lbl_lac_top.pack(anchor="w")

        tech_f = tk.Frame(info_main, bg="#ecf0f1")
        tech_f.grid(row=0, column=2, sticky="nw", pady=20)
        self.lbl_type = tk.Label(tech_f, text="Typ: --", font=("Arial", 11, "bold"), bg="#ecf0f1", fg="#d35400")
        self.lbl_type.pack(anchor="w")
        self.lbl_freq = tk.Label(tech_f, text="Frequenz: --", font=("Arial", 11), bg="#ecf0f1", fg="#2980b9")
        self.lbl_freq.pack(anchor="w")
        self.lbl_bw = tk.Label(tech_f, text="Bandbreite: -- MHz", font=("Arial", 11), bg="#ecf0f1")
        self.lbl_bw.pack(anchor="w")
        self.lbl_mcc = tk.Label(tech_f, text="MCC: --", font=("Arial", 11), bg="#ecf0f1")
        self.lbl_mcc.pack(anchor="w")
        self.lbl_mnc = tk.Label(tech_f, text="MNC: --", font=("Arial", 11), bg="#ecf0f1")
        self.lbl_mnc.pack(anchor="w")
        self.lbl_oper = tk.Label(tech_f, text="Betreiber: --", font=("Arial", 11, "italic"), bg="#ecf0f1", fg="#2c3e50")
        self.lbl_oper.pack(anchor="w")
        
        sim_box = tk.LabelFrame(info_main, text=" SIM-Karte und Gerät ", bg="#bdc3c7", font=("Arial", 9, "bold"))
        sim_box.grid(row=0, column=3, sticky="nsew", padx=10, pady=10)
        self.lbl_sim = tk.Label(sim_box, text="Nummer: --\nIMSI: --\nICCID: --\n\nIMEI: --\nGerät: --, --\nFirmwarerevision: --", 
                               bg="#bdc3c7", font=("Consolas", 9), justify=tk.LEFT, anchor="nw")
        self.lbl_sim.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.main_container = tk.Frame(self.root, bg="#2c3e50")
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.hist_frame = tk.LabelFrame(self.main_container, text=" Funkzellen-Historie ", bg="#2c3e50", fg="white", font=("Arial", 10, "bold"))
        self.cell_table = scrolledtext.ScrolledText(self.hist_frame, bg="#1e272e", fg="#0be881", font=("Consolas", 10))
        self.cell_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.vorgaben_frame = tk.LabelFrame(self.main_container, text=" Mobilfunk-Vorgaben ", bg="#2c3e50", fg="white", font=("Arial", 10, "bold"))
        self.vorgaben_table = tk.Text(self.vorgaben_frame, bg="#1e272e", font=("Consolas", 10), height=4)
        self.vorgaben_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.vorgaben_table.tag_config("normal", foreground="#0be881")
        self.vorgaben_table.tag_config("warn", foreground="orange")

        self.reichweite_frame = tk.LabelFrame(self.main_container, text=" Funkzellen in Reichweite ", bg="#2c3e50", fg="white", font=("Arial", 10, "bold"))
        self.reichweite_table = tk.Text(self.reichweite_frame, bg="#1e272e", font=("Consolas", 10))
        self.reichweite_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.reichweite_table.tag_config("tuerkis", foreground="#00d2d3")
        self.reichweite_table.tag_config("grau", foreground="gray")

        self.log_frame = tk.LabelFrame(self.main_container, text=" System-Log (Statusmeldungen) ", bg="#2c3e50", fg="white", font=("Arial", 10, "bold"))
        self.system_log = scrolledtext.ScrolledText(self.log_frame, bg="#1e272e", fg="#e84118", font=("Consolas", 9))
        self.system_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.apply_layout()

        if hasattr(self, 'saved_orientation') and self.saved_orientation:
            self.is_vertical = False
            self.toggle_view()

        self.draw_gauge_base()

    def apply_layout(self):
        for f in [self.hist_frame, self.vorgaben_frame, self.reichweite_frame, self.log_frame]:
            f.pack_forget()
            f.place_forget()
            f.pack_propagate(True)

        if self.is_vertical:
            self.vorgaben_frame.config(height=80)
            self.vorgaben_frame.pack_propagate(False)
            self.vorgaben_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
            
            self.log_frame.config(height=100)
            self.log_frame.pack_propagate(False)
            self.log_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

            self.reichweite_frame.config(height=150)
            self.reichweite_frame.pack_propagate(False)
            self.reichweite_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

            self.hist_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=2)
        else:
            self.hist_frame.place(relx=0, rely=0, relwidth=0.64, relheight=0.78)
            self.log_frame.place(relx=0, rely=0.79, relwidth=0.64, relheight=0.21)
            self.vorgaben_frame.place(relx=0.65, rely=0, relwidth=0.35, relheight=0.30)
            self.reichweite_frame.place(relx=0.65, rely=0.31, relwidth=0.35, relheight=0.69)

    def toggle_view(self):
        self.is_vertical = not self.is_vertical
        self.apply_layout()
        
    def show_debug_window(self):
        debug_win = tk.Toplevel(self.root)
        debug_win.title("Modem Raw Data")
        debug_win.geometry("950x500")
        debug_win.configure(bg="#1a1a1a")

        debug_text = scrolledtext.ScrolledText(debug_win, bg="black", fg="#00ff00", font=("Consolas", 10))
        debug_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
    def switch_profile(self):
        self.current_profile_idx = (self.current_profile_idx + 1) % len(self.cmd_profiles)
        cmd, name = self.cmd_profiles[self.current_profile_idx]
        self.lbl_profile_name.config(text=f"Profil: {name}")
        self.sys_log(f"Befehlssatz gewechselt zu: {name}")

    def update_vorgaben(self, rach, pusch, pstep, retx, cipher):
        self.vorgaben_table.delete('1.0', tk.END)
        header = f"{'RACH':<8} {'PUSCH':<8} {'P.Step':<8} {'Max.ReTX':<10} {'Ciphering Mode'}\n"
        sep = "-" * 55 + "\n"
        self.vorgaben_table.insert(tk.END, header, "normal")
        self.vorgaben_table.insert(tk.END, sep, "normal")

        tag_rach = "warn" if rach >= -90 else "normal"
        self.vorgaben_table.insert(tk.END, f"{rach}dBm".ljust(9), tag_rach)

        tag_pusch = "warn" if pusch >= -70 else "normal"
        self.vorgaben_table.insert(tk.END, f"{pusch}dBm".ljust(9), tag_pusch)

        tag_pstep = "warn" if pstep >= 4 else "normal"
        self.vorgaben_table.insert(tk.END, f"{pstep}dBm".ljust(9), tag_pstep)

        tag_retx = "warn" if retx >= 8 else "normal"
        self.vorgaben_table.insert(tk.END, f"{retx}x".ljust(11), tag_retx)

        c_map = {
            "A5/0": ("A5/0: Keine Verschlüsselung", "warn"),
            "A5/1": ("A5/1: veraltete Verschlüsselung", "warn"),
            "A5/2": ("A5/2: geschwächte Verschlüsselung", "warn"),
            "A5/3": ("A5/3: aktuelle Verschlüsselung", "normal"),
            "A5/4": ("A5/4: Moderne Verschlüsselung", "normal"),
            "A5/5": ("A5/5: Moderne Verschlüsselung", "normal"),
            "0": ("0: keine Verschlüsselung", "warn"),
            "1": ("1: SNOW-verschlüsselt", "normal"),
            "2": ("2: AES-verschlüsselt", "normal"),
            "3": ("3: ZUC-verschlüsselt", "normal")
        }
        c_txt, c_tag = c_map.get(str(cipher), ("Unbekannt", "warn"))
        self.vorgaben_table.insert(tk.END, c_txt, c_tag)

    def update_neighbor_display(self):
        self.reichweite_table.delete('1.0', tk.END)
        header = f"{'Uhrzeit':<10} {'Band':<10} {'Kanal':<8} {'PCI':<6} {'RSSI'}\n"
        self.reichweite_table.insert(tk.END, header, "tuerkis")
        self.reichweite_table.insert(tk.END, "-"*50 + "\n", "tuerkis")
        
        sorted_cells = sorted(self.neighbor_cells.values(), 
                             key=lambda x: (x['active'], x['rssi']), reverse=True)
        
        for c in sorted_cells:
            tag = "tuerkis" if c['active'] else "grau"
            line = f"{c['time']:<10} {c['band']:<10} {c['ch']:<8} {c['pci']:<6} {c['rssi']}dBm\n"
            self.reichweite_table.insert(tk.END, line, tag)

    def update_neighbors(self, raw_data=None):
        if not hasattr(self, 'reichweite_table'):
            return

        try:
            jetzt = time.strftime('%H:%M:%S')
            
            if raw_data:
                matches = re.findall(r'(\d+)\s*,\s*(\d+)\s*,\s*(-?\d+)', raw_data)
                for match in matches:
                    c_id = int(match[0])
                    p_id = match[1]
                    r_val = int(match[2])
                    b_name = "Unbekannt"
                    for b_start, b_end, n in self.bands:
                        if b_start <= c_id <= b_end:
                            b_name = n
                            break
                    self.neighbor_cells[c_id] = {
                        'time': jetzt, 'band': b_name, 'ch': c_id, 'pci': p_id, 'rssi': r_val
                    }

            self.reichweite_table.delete('1.0', tk.END)
            h = f"{'Uhrzeit':<10} {'Band':<18} {'Kanal':<10} {'PCI':<6} {'RSSI'}\n"
            self.reichweite_table.insert(tk.END, h, "tuerkis")
            self.reichweite_table.insert(tk.END, "-"*55 + "\n", "tuerkis")
            
            n_list = []
            for k, d in self.neighbor_cells.items():
                n_list.append({
                    'cid': k, 'time': d.get('time', jetzt),
                    'band': d.get('band', '--'), 
                    'pci': d.get('pci', '--'), 
                    'rssi': d.get('rssi', -140)
                })
            
            n_list.sort(key=lambda x: x['rssi'], reverse=True)
            
            a_chan = getattr(self, 'last_chan', "--")
            if a_chan == "--":
                f_text = self.lbl_freq.cget("text")
                c_match = re.search(r'Kanal:\s*(\d+)', f_text)
                a_chan = c_match.group(1) if c_match else "--"

            a_band_text = "--"
            if a_chan != "--":
                c_num = int(a_chan)
                for b_start, b_end, name in self.bands:
                    if b_start <= c_num <= b_end:
                        a_band_text = name
                        break
            
            if a_band_text == "--":
                tech_map = {"0":"GSM", "1":"GSM", "2":"3G", "6":"LTE", "7":"LTE", "10":"LTE-M"}
                raw_tech = str(getattr(self, 'current_act', ""))
                a_band_text = tech_map.get(raw_tech, "Funk")

            a_pci = "--"
            if raw_data:
                pci_match = re.search(r'(?:pci|phys_id|PCI)[\s:=,]+(\d+)', raw_data, re.IGNORECASE)
                if pci_match:
                    a_pci = pci_match.group(1)
                else:
                    parts = re.findall(r'(\d+)', raw_data)
                    if len(parts) > 1:
                        if len(parts) > 2 and parts[0] == str(a_chan):
                            a_pci = parts[1]
                        elif len(parts) == 2:
                            a_pci = parts[1]

            if a_pci == "--" and hasattr(self, 'current_pci'):
                a_pci = str(self.current_pci)

            a_rssi = getattr(self, 'current_dbm', "--")
            a_time = getattr(self, 'start_ts', jetzt)
            act_ch_str = str(a_chan)
            
            n_list = [c for c in n_list if str(c['cid']) != act_ch_str]
            
            line = f"{a_time:<10} {a_band_text:<18} {act_ch_str + ' (Aktiv)':<10} {a_pci:<6} {a_rssi} dBm\n"
            self.reichweite_table.insert(tk.END, line, "tuerkis")

            for c in n_list:
                l = f"{c['time']:<10} {c['band']:<18} {c['cid']:<10} {c['pci']:<6} {c['rssi']} dBm\n"
                self.reichweite_table.insert(tk.END, l, "grau")
            
        except Exception as e:
                    if hasattr(self, 'log_text') and self.log_text.winfo_exists():
                        self.log_text.insert("end", f"{time.strftime('%H:%M:%S')} - [FEHLER]: {str(e)}\n")
                        self.log_text.see("end")
                    elif hasattr(self, 'debug_text_widget') and self.debug_text_widget.winfo_exists():
                        self.debug_text_widget.insert("end", f"\n[FEHLER] {time.strftime('%H:%M:%S')}: {str(e)}\n", "stream_out")
                        self.debug_text_widget.see("end")
                    time.sleep(1.0)

    def sys_log(self, msg, level="INFO"):
        prefix = ">>> " if level == "ERR" else ""
        self.system_log.insert("1.0", f"[{time.strftime('%H:%M:%S')}] {prefix}{msg}\n")

    def reset_logs(self):
        self.history_data = []
        self.neighbor_cells = {}
        self.cell_table.delete('1.0', tk.END)
        self.system_log.delete('1.0', tk.END)
        self.vorgaben_table.delete('1.0', tk.END)
        self.reichweite_table.delete('1.0', tk.END)
        self.sys_log("Logs zurückgesetzt.")

    def copy_history(self):
        content = self.cell_table.get("1.0", tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.sys_log("Kopiert.")

    def draw_gauge_base(self):
        self.canvas.create_arc(20, 30, 200, 210, start=0, extent=180, outline="#7f8c8d", width=3, style=tk.ARC)
        for i in range(11):
            angle = math.radians(180 - (i * 18))
            x1, y1 = 110 + 80 * math.cos(angle), 120 - 80 * math.sin(angle)
            x2, y2 = 110 + 90 * math.cos(angle), 120 - 90 * math.sin(angle)
            self.canvas.create_line(x1, y1, x2, y2, fill="#7f8c8d", width=2)
        self.needle = self.canvas.create_line(110, 120, 30, 120, fill="#e74c3c", width=4, capstyle=tk.ROUND)

    def update_gauge(self, dbm):
        val = max(0, min(100, (dbm + 113) * 1.6))
        angle = math.radians(180 - (val * 1.8))
        x, y = 110 + 80 * math.cos(angle), 120 - 80 * math.sin(angle)
        self.canvas.coords(self.needle, 110, 120, x, y)

    def toggle_connection(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            self.ser = None
            self.btn_connect.config(text="START", bg="#27ae60")
            self.sys_log("Verbindung getrennt.")
        else:
            try:
                self.sys_log(f"Verbinde mit {self.port_combo.get()}...")
                self.ser = serial.Serial(self.port_combo.get(), 115200, timeout=1.5)
                self.btn_connect.config(text="STOPP", bg="#c0392b")
                self.ser.write(b'AT\r')
                time.sleep(0.5)

                def get_clean_at_res(cmd):
                    self.ser.write(cmd + b'\r')
                    time.sleep(0.5)
                    raw = self.ser.read_all().decode(errors='ignore').strip()
                    lines = [line.strip() for line in raw.splitlines() 
                             if line.strip() and not line.upper().startswith('AT') 
                             and line.upper() != 'OK' and not line.startswith('*')]
                    return lines[0] if lines else "--"

                self.imei = get_clean_at_res(b'AT+CGSN')
                self.hersteller = get_clean_at_res(b'AT+CGMI')
                self.modell = get_clean_at_res(b'AT+CGMM')
                self.revision = get_clean_at_res(b'AT+CGMR')

                iccid = "--"
                for cmd in [b'AT+CCID\r', b'AT^ICCID?\r', b'AT+QCCID\r', b'AT+CRSM=176,12258,0,0,10\r']:
                    self.ser.write(cmd)
                    time.sleep(1.0)
                    res = self.ser.read_all().decode(errors='ignore')
                    found = re.findall(r'(\d{15,22})', res)
                    if found:
                        iccid = found[0]
                        break
                
                self.ser.write(b'AT+CIMI\r')
                time.sleep(0.6)
                imsi_res = self.ser.read_all().decode(errors='ignore')
                imsi_match = re.findall(r'\d{10,20}', imsi_res)
                imsi = imsi_match[0] if imsi_match else "--"

                self.ser.write(b'AT+CNUM\r')
                time.sleep(0.6)
                num_res = self.ser.read_all().decode(errors='ignore')
                num_m = re.search(r'"(\+?\d+)"', num_res)
                num = num_m.group(1) if num_m else "--"

                self.lbl_sim.config(text=f"Nummer: {num}\nIMSI: {imsi}\nICCID: {iccid}\n\n"
                                         f"IMEI: {self.imei}\n"
                                         f"Gerät: {self.hersteller}, {self.modell}\n"
                                         f"Firmwarerevision: {self.revision}")
                
                self.ser.write(b'AT+CREG=2\r')
                time.sleep(0.5)
                self.sys_log("Starte Live-Update...")
                threading.Thread(target=self.update_loop, daemon=True).start()
                self.root.after(2000, self.update_neighbors)
            except Exception as e:
                self.sys_log(f"Fehler: {e}", "ERR")
                self.lbl_sim.config(text=f"Nummer: {num}\nIMSI: {imsi}\nICCID: {iccid}\n\n"
                                         f"IMEI: {self.imei}\n"
                                         f"Gerät: {self.hersteller}, {self.modell}\n"
                                         f"Firmwarerevision: {self.revision}")

    def update_loop(self):
        while self.running:
            if self.ser and self.ser.is_open:
                try:
                    cmd_csq = b'AT+CSQ\r'
                    self.ser.write(cmd_csq)
                    time.sleep(0.4)
                    res_csq = self.ser.read_all().decode(errors='ignore')
                    
                    if self.debug_streaming and hasattr(self, 'debug_text_widget') and self.debug_text_widget.winfo_exists():
                        if not getattr(self, 'filter_active', False):
                            self.debug_text_widget.insert("end", f"\n[OUT] AT+CSQ\n", "stream_out")
                            self.debug_text_widget.insert("end", f"[IN]  {res_csq.strip()}\n", "stream_in")
                            self.debug_text_widget.see("end")

                    dbm = -113
                    csq = re.search(r'\+CSQ:\s*(\d+)', res_csq)
                    if csq and csq.group(1) != "99":
                        self.current_dbm = -113 + (int(csq.group(1)) * 2)
                        self.lbl_dbm.config(text=f"Signal: {self.current_dbm} dBm")
                        self.update_gauge(self.current_dbm)

                    cmd_srv = self.cmd_profiles[self.current_profile_idx][0]
                    self.ser.write(cmd_srv)
                    time.sleep(1.2)
                    res_srv = self.ser.read_all().decode(errors='ignore')
                    
                    if self.debug_streaming and hasattr(self, 'debug_text_widget') and self.debug_text_widget.winfo_exists():
                        if not getattr(self, 'filter_active', False):
                            self.debug_text_widget.insert("end", f"\n[OUT] {cmd_srv.decode().strip()}\n", "stream_out")
                            self.debug_text_widget.insert("end", f"[IN]  {res_srv.strip()}\n", "stream_in")
                            self.debug_text_widget.see("end")
                    
                    chan = None
                    f_match = re.search(r'(?:ch|kanal|arfcn|earfcn)[\s:=,]+(\d+)', res_srv, re.IGNORECASE)
                    if f_match:
                        chan = int(f_match.group(1))
                    if not chan:
                        all_vals = re.findall(r'\d+', res_srv)
                        for v in all_vals:
                            num = int(v)
                            if any(b[0] <= num <= b[1] for b in self.bands):
                                chan = num
                                break
                    
                    if chan:
                        self.last_chan = str(chan)
                        
                        pci_active = re.search(r'(?:pci|phys_id|PCI)[\s:=,]+(\d+)', res_srv, re.IGNORECASE)
                        if pci_active:
                            self.current_pci = pci_active.group(1)
                        else:
                            parts = re.findall(r'(\d+)', res_srv)
                            if len(parts) > 2:
                                self.current_pci = parts[1]

                        b_name = "Unbekannt"
                        for b_start, b_end, n in self.bands:
                            if b_start <= chan <= b_end:
                                b_name = n
                                break
                        self.current_band_name = b_name
                        f_details = self.get_full_freq_info(chan)
                        self.lbl_freq.config(text=f"Frequenz: {f_details}")
                        self.update_neighbors(res_srv)
                    else:
                        self.lbl_freq.config(text="Frequenz: Suche...")

                    current_type = self.lbl_type.cget("text")
                    bw_val = "--"
                    bw_match = re.search(r'(?:BW|Bandwidth|width|mhz)[\s:=,]+(\d+)', res_srv, re.IGNORECASE)
                    if bw_match:
                        v = int(bw_match.group(1))
                        bw_map = {0:1.4, 1:3, 2:5, 3:10, 4:15, 5:20, 6:1.4, 15:3, 25:5, 50:10, 75:15, 100:20}
                        bw_val = str(bw_map.get(v, v if v < 50 else v/10))
                    
                    if bw_val == "--" or bw_val == "":
                        if "LTE" in current_type: bw_val = "10"
                        elif "UMTS" in current_type: bw_val = "5"
                        elif "GSM" in current_type: bw_val = "0.2"

                    self.lbl_bw.config(text=f"Bandbreite: {bw_val} MHz")
                    self.update_vorgaben(-104, -90, 2, 4, "2")

                    for cmd in [b'AT+CREG?\r', b'AT+CEREG?\r']:
                        self.ser.write(cmd)
                        time.sleep(0.4)
                        res_reg = self.ser.read_all().decode(errors='ignore')
                        
                        reg_match = re.search(r'\+C[E]?REG:\s*\d+,(\d+)(?:,["\']([0-9A-Fa-f]+)["\']\s*,\s*["\']([0-9A-Fa-f]+)["\'])?', res_reg)
                        if reg_match:
                            stat_code = reg_match.group(1)
                            status_map = {
                                "0": ("Nicht registriert", "#c23616"),
                                "1": ("Heimatnetz", "#44bd32"),
                                "2": ("Netzsuche", "#e67e22"),
                                "3": ("Abgelehnt", "#e84118"),
                                "4": ("außer Reichweite", "#f39c12"),
                                "5": ("Roaming", "#0097e6"),
                                "6": ("unbekannt", "#7f8c8d")
                            }
                            txt, color = status_map.get(stat_code, ("Unbekannt", "#7f8c8d"))
                            self.lbl_status.config(text=f"Status: {txt}", fg=color)

                            if reg_match.group(2) and reg_match.group(3):
                                l_dec, c_dec = int(reg_match.group(2), 16), int(reg_match.group(3), 16)
                                self.lbl_lac_top.config(text=f"LAC: {l_dec}")
                                self.lbl_cid_top.config(text=f"Cell-ID: {c_dec}")
                                
                                if c_dec != self.last_cid:
                                    if self.last_cid is not None:
                                        dur = time.strftime('%H:%M:%S', time.gmtime(time.time() - self.cell_start_time))
                                        self.history_data.insert(0, f"{self.start_ts:<10} {self.last_lac:<8} {self.last_cid:<12} {self.current_max_dbm:<10} {dur}")
                                    
                                    self.last_cid, self.last_lac = c_dec, l_dec
                                    self.start_ts = time.strftime('%H:%M:%S')
                                    self.cell_start_time = time.time()
                                    self.current_max_dbm = self.current_dbm
                                
                                if self.current_dbm > -113:
                                    if self.current_max_dbm <= -113:
                                        self.current_max_dbm = self.current_dbm
                                    else:
                                        self.current_max_dbm = max(self.current_max_dbm, self.current_dbm)

                                self.cell_table.delete('1.0', tk.END)
                                self.cell_table.insert(tk.END, f"{'Uhrzeit':<10} {'LAC':<8} {'Cell-ID':<12} {'dBm (max)':<10} {'Status'}\n" + "-"*60 + "\n")
                                disp_dbm = self.current_max_dbm if self.current_max_dbm > -113 else "--"
                                self.cell_table.insert(tk.END, f"{self.start_ts:<10} {l_dec:<8} {c_dec:<12} {disp_dbm:<10} {'Aktiv'}\n")
                                for entry in self.history_data:
                                    self.cell_table.insert(tk.END, entry + "\n")

                    cmd_cops = b'AT+COPS=3,2;+COPS?\r'
                    self.ser.write(cmd_cops)
                    time.sleep(0.5)
                    res_cops = self.ser.read_all().decode(errors='ignore')
                    
                    if self.debug_streaming and hasattr(self, 'debug_text_widget') and self.debug_text_widget.winfo_exists():
                        if not getattr(self, 'filter_active', False):
                            self.debug_text_widget.insert("end", f"\n[OUT] AT+COPS?\n", "stream_out")
                            self.debug_text_widget.insert("end", f"[IN]  {res_cops.strip()}\n", "stream_in")
                            self.debug_text_widget.see("end")

                    cops = re.search(r'\+COPS:\s*(\d+),(\d+),"(\d+)",?(\d)?', res_cops)
                    if cops:
                        net_code = cops.group(3)
                        self.current_act = cops.group(4) if cops.group(4) else "0"
                        self.lbl_mcc.config(text=f"MCC: {net_code[:3]}")
                        self.lbl_mnc.config(text=f"MNC: {net_code[3:]}")
                        self.lbl_oper.config(text=f"Betreiber: {self.mnc_dict.get(net_code[3:], 'Vodafone DE')}")
                        t = {"0":"GSM (2G)", "1":"GSM Compact (2G)", "2":"UTRAN (3G)", "3":"GSM/EDGE (2G)", "4":"HSDPA (3G)", "5":"HSDPA (3G)", "6":"E-UTRAN/LTE (4G)", "7":"E-UTRAN/LTE (4G)", "8":"EC-GSM-IoT (2G)", "9":"E-UTRAN NB-S1 (NB-IoT)", "10":"E-UTRAN/LTE-M (4G)"}.get(self.current_act, "Funk")
                        self.lbl_type.config(text=f"Typ: {t}")
                    time.sleep(1.0)
                except:
                    pass
            else:
                time.sleep(1)

    def show_debug_window(self):
        debug_win = tk.Toplevel(self.root)
        debug_win.title("Modem Expert-Schnittstelle (Rohdaten & Diagnose)")
        debug_win.geometry("950x500")
        debug_win.configure(bg="#1a1a1a")
        
        self.debug_streaming = False
        self.filter_active = False
        
        self.debug_text_widget = scrolledtext.ScrolledText(debug_win, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.debug_text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        self.debug_text_widget.tag_config("diag_header", foreground="#f1c40f", font=("Consolas", 10, "bold"))
        self.debug_text_widget.tag_config("diag_ok", foreground="#2ecc71")
        self.debug_text_widget.tag_config("diag_err", foreground="#e74c3c")
        self.debug_text_widget.tag_config("raw_in", foreground="#3498db", background="#000033")
        self.debug_text_widget.tag_config("raw_out", foreground="yellow", background="#000033")
        self.debug_text_widget.tag_config("stream_in", foreground="#3498db")
        self.debug_text_widget.tag_config("stream_out", foreground="#e74c3c")

        cmd_frame = tk.Frame(debug_win, bg="#1a1a1a")

        def toggle_filter():
            self.filter_active = not self.filter_active
            if self.filter_active:
                btn_filter.configure(bg="#2ecc71", text="Filter: EIN")
            else:
                btn_filter.configure(bg="#bdc3c7", text="Filter: AUS")

        btn_filter = tk.Button(cmd_frame, text="Filter: ", command=toggle_filter, bg="#bdc3c7", fg="black", width=10, font=("Arial", 9, "bold"))
        btn_filter.pack(side=tk.LEFT, padx=5)
        
        def send_custom_command(event=None):
            cmd = entry_cmd.get().strip()
            if not cmd:
                return
            if not self.ser or not self.ser.is_open:
                self.debug_text_widget.insert(tk.END, "FEHLER: Keine Verbindung!\n", "diag_err")
                return
            try:
                full_cmd = (cmd + "\r").encode()
                self.ser.write(full_cmd)
                self.debug_text_widget.insert(tk.END, f"\n[USER-OUT] {cmd}\n", "raw_out")
                entry_cmd.delete(0, tk.END)
                def read_res():
                    time.sleep(0.5)
                    res = self.ser.read_all().decode(errors='ignore').strip()
                    if res:
                        self.debug_text_widget.insert(tk.END, f"[USER-IN]  {res}\n", "raw_in")
                        self.debug_text_widget.see(tk.END)
                threading.Thread(target=read_res, daemon=True).start()
            except Exception as e:
                err_msg = f"{time.strftime('%H:%M:%S')} - [FEHLER]: {str(e)}\n"
                if hasattr(self, 'log_widget') and self.log_widget.winfo_exists():
                    self.log_widget.insert("end", err_msg, "error")
                    self.log_widget.see("end")
                else:
                    print(err_msg)
                
                time.sleep(1.0)
                
                if hasattr(self, 'debug_text_widget') and self.debug_text_widget.winfo_exists():
                    self.debug_text_widget.insert(tk.END, f"Fehler im Ablauf: {e}\n", "diag_err")
                    self.debug_text_widget.see("end")

        def run_full_diagnose():
            if not self.ser or not self.ser.is_open:
                self.debug_text_widget.insert(tk.END, "FEHLER: Keine serielle Verbindung!\n", "diag_err")
                return
            
            self.debug_text_widget.insert(tk.END, f"\n--- STARTE EINMALIGEN HERSTELLER-SUPPORT-CHECK ({time.strftime('%H:%M:%S')}) ---\n", "diag_header")
            
            diag_cmds = [
                ("ATI", "Basis Info"), ("AT+GMM", "Modell"), 
                ("AT+CPMS?", "Speicher-Status"), ("AT+CSQ", "Signalstärke Standard"),
                ("AT*E2EMSRV", "Dell/Ericsson Engineering"), ("AT*ELNM", "Netzwerkliste"),
                ("AT+SURSERV", "Ericsson Serving Cell"), ("AT+COPS?", "Netzbetreiber Info"),
                ("AT+GCI?", "Ericsson Herkunft"), ("AT+ESMON?", "Ericsson Monitoring"),
                ("AT$QCRSRP", "Qualcomm RSRP Info"), ("AT$QCRSRQ", "Qualcomm RSRQ Info"),
                ("AT$QCPWR", "Qualcomm Power Stats"), ("AT+QNETDEVCTL?", "Qualcomm Network Data"),
                ("AT+ESLP?", "MediaTek Sleep Status"), ("AT+EMCA?", "MediaTek Carrier Aggregation"),
                ("AT+EMSRV?", "MediaTek Service Info"), ("AT+EINFO", "MediaTek Engineering"),
                ("AT+XLOG?", "Intel/Apple Logging"), ("AT+XREG?", "Intel/Apple Network Status"),
                ("AT+XACT?", "Intel/Apple Active RAT"), ("AT+XNR5G?", "Intel/Apple 5G Info"),
                ("AT^HCSQ?", "Huawei Signal (LTE)"), ("AT^SYSINFO", "Huawei Systemstatus"), 
                ("AT^NWINFO", "Huawei Tech/Band"), ("AT+QENG=\"servingcell\"", "Quectel Serving Cell"), 
                ("AT+QENG=\"neighbourcell\"", "Quectel Neighbors"), ("AT+QCAINFO", "Quectel Carrier Aggregation"),
                ("AT!GSTATUS?", "Sierra Dashboard"), ("AT!SELRAT?", "Sierra Mode Status"),
                ("AT^SMONI", "Gemalto Monitoring"), ("AT^SIND", "Gemalto Indikatoren"),
                ("AT#RFSTS", "Telit Radio Stats"), ("AT#SERVINFO", "Telit Service"),
                ("AT+CPSI?", "SimCom Systeminfo"), ("AT+UCEDATA?", "u-blox Engineering"),
                ("AT+ZCELLINFO?", "ZTE Cell Info"), ("AT+MODEMINFO", "Samsung Hardware"),
                ("AT+NUESTATS", "Neul/HiSilicon Stats"), ("AT!BAND?", "Sierra Band Konfig"), 
                ("AT+QNWINFO", "Quectel All-in-One"), ("AT+QADC=0", "Quectel ADC/Volt"), 
                ("AT#TEMPMON", "Telit Temperatur"), ("AT^ANTENNA", "Huawei Antennen-Status"),
                ("AT+CSURV", "Standard Network Survey")
            ]

            for cmd_str, label in diag_cmds:
                full_cmd = (cmd_str + "\r").encode()
                self.debug_text_widget.insert(tk.END, f"Prüfe {label} ({cmd_str})... ", "diag_header")
                self.debug_text_widget.see(tk.END)
                self.root.update_idletasks()
                
                try:
                    self.ser.write(full_cmd)
                    time.sleep(0.6)
                    res = self.ser.read_all().decode(errors='ignore').strip()
                    if res and "ERROR" not in res.upper():
                        self.debug_text_widget.insert(tk.END, "SUPPORTED\n", "diag_ok")
                        self.debug_text_widget.insert(tk.END, f"{res}\n\n")
                    else:
                        self.debug_text_widget.insert(tk.END, "not supported\n")
                except:
                    self.debug_text_widget.insert(tk.END, "Timeout/Fehler\n")
            
            self.debug_text_widget.insert(tk.END, "--- CHECK BEENDET ---\n\n", "diag_header")
            self.debug_text_widget.see(tk.END)

        def toggle_raw():
            self.debug_streaming = not self.debug_streaming
            if self.debug_streaming:
                btn_raw.config(text="STOP")
                cmd_frame.pack(pady=10, fill=tk.X, padx=20)
            else:
                btn_raw.config(text="RawData")
                cmd_frame.pack_forget()

        btn_frame = tk.Frame(debug_win, bg="#1a1a1a")
        btn_frame.pack(pady=5)
        
        btn_raw = tk.Button(btn_frame, text="RawData", command=toggle_raw, bg="#f1c40f", fg="black", width=15, font=("Arial", 10, "bold"))
        btn_raw.pack(side=tk.LEFT, padx=5)

        btn_debug = tk.Button(btn_frame, text="DEBUG", command=run_full_diagnose, bg="#8b0000", fg="white", width=15, font=("Arial", 10, "bold"))
        btn_debug.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Log löschen", command=lambda: self.debug_text_widget.delete('1.0', tk.END), bg="#7f8c8d", fg="white", width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Alles kopieren", command=lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self.debug_text_widget.get("1.0", tk.END))), bg="#2c3e50", fg="white", width=15).pack(side=tk.LEFT, padx=5)

        entry_cmd = tk.Entry(cmd_frame, bg="#2c3e50", fg="white", insertbackground="white", font=("Consolas", 11))
        entry_cmd.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        entry_cmd.bind("<Return>", send_custom_command)
        
        btn_send = tk.Button(cmd_frame, text="Senden", command=send_custom_command, bg="#27ae60", fg="white", width=10, font=("Arial", 10, "bold"))
        btn_send.pack(side=tk.LEFT, padx=5)

        def on_close():
            self.debug_streaming = False
            debug_win.destroy()
        debug_win.protocol("WM_DELETE_WINDOW", on_close)

if __name__ == "__main__":
    root = tk.Tk(); app = AdvancedCellAnalyzer(root)
    
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    root.mainloop()