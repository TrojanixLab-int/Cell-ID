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
        self.root.withdraw()
        self.window_x = 0
        self.window_y = 0
        self.window_state = "normal"
        self.load_settings()
        self.root.geometry(f"1370x780+{self.window_x}+{self.window_y}")
        self.root.deiconify()
        if self.window_state == "zoomed":
            self.root.state("zoomed")
        import os
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cell-ID.ico")
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        self.root.title("Mobilfunkzellen-Analyzer v2.1.2 - M. Trojan")
        self.root.configure(bg="#2c3e50")

        self.default_config = {"port": "", "profile": 0}

        self.call_window = None
        self.last_call_info = {"number": "", "time": 0}
        self.call_timer = None
        self.call_log_index = None
        self.call_number = None
        self.call_active = False
        self.active_cell_events = {}
        self.call_start_time = 0
        self.last_ring_time = 0
        self.call_status = None
        self.call_start_time = None
        self.call_logged = False
        self.clip_received = False
        self.call_ignored = False

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
        
        self.last_finish_time = 0
        
        self.debug_streaming = False
        
        self.mnc_dict = {        #Liste der Netzbetreiber (Stand: 02-2026)
            "01": "Telekom DE", "06": "Telekom DE", 
            "02": "Vodafone DE", "04": "Vodafone DE", "09": "Vodafone DE", 
            "03": "Telefónica DE", "05": "O2 Telefónica DE", #ehemals E-Plus
            "07": "Telefónica DE", "08": "O2 Telefónica DE", "11": "Telefónica DE", #ehemals O2
            "10": "Quam", "60": "DBInfraGo AG", "13": "BAAINBw", 
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
            log_content = self.system_log.get("1.0", tk.END).strip().replace("\n", "|LINE|")
            hist_content = self.cell_table.get("1.0", tk.END).strip().replace("\n", "|LINE|")

            with open("config.txt", "w", encoding='utf-8') as f:
                port = self.port_combo.get() 
                profile = self.current_profile_idx 
                orientation = "1" if self.is_vertical else "0"
                f.write(f"{port}\n{profile}\n{orientation}\n{log_content}\n{hist_content}")
                f.write(f"\n{self.window_x}\n{self.window_y}\n{self.window_state}")
        except Exception as e:
            print(f"Fehler beim Speichern: {e}")

    def save_report_to_file(self):
        import os
        import subprocess
        d = "gespeichert"
        if not os.path.exists(d):
            os.makedirs(d)
        today = time.strftime("%Y-%m-%d")
        for i in range(1, 100):
            fn = f"Bericht_{today}_{i:02d}.txt"
            fp = os.path.join(d, fn)
            if not os.path.exists(fp):
                break
        t = "   "
        raw_sim_text = self.lbl_sim.cget("text")
        sim_data = raw_sim_text.split("\n")
        while len(sim_data) < 7:
            sim_data.append("")
        r = f"Mobilfunkzellen-Analyzer - Bericht: {time.strftime('%Y-%m-%d, %H:%M:%S')}\n\n"
        r += f"+ SIM-Karte und Gerät:\n{t}{sim_data[0]}\n{t}{sim_data[1]}\n{t}{sim_data[2]}\n\n{t}{sim_data[4]}\n{t}{sim_data[5]}\n{t}{sim_data[6]}\n\n"
        r += f"+ Befehlssatzprofil:\n{t}{self.lbl_profile_name.cget('text')}\n\n\n"
        r += f"+ Aktives Netz:\n{t}{self.lbl_status.cget('text')}\n{t}Signal: {self.lbl_dbm.cget('text')}\n{t}{self.lbl_mcc.cget('text')}\n{t}{self.lbl_mnc.cget('text')}\n{t}{self.lbl_lac_top.cget('text')}\n{t}{self.lbl_cid_top.cget('text')}\n{t}{self.lbl_oper.cget('text')}\n{t}{self.lbl_type.cget('text')}\n{t}{self.lbl_freq.cget('text')}\n{t}{self.lbl_bw.cget('text')}\n\n\n"
        r += f"+ Mobilfunkvorgaben:\n{self.vorgaben_table.get('1.0', tk.END)}\n\n"
        r += f"+ Funkzellen in Reichweite bei aktiver Funkzelle:\n{self.reichweite_table.get('1.0', tk.END)}\n\n"
        r += f"+ Funkzellen-Historie\n{self.cell_table.get('1.0', tk.END)}\n"
        r += f"+ System-Log (Statusmeldungen)\n\n{self.system_log.get('1.0', tk.END)}\n-------------------------------------------------------\n"

        if hasattr(self, 'debug_text_widget') and self.debug_text_widget.winfo_exists():
            debug_content = self.debug_text_widget.get('1.0', tk.END).strip()
            if not debug_content:
                debug_content = "(nicht ausgeführt)"
        else:
            debug_content = "(nicht ausgeführt)"

        r += f"+ ausgelesene Rohdaten & Diagnosedaten:\n\n{debug_content}"
        with open(fp, "w", encoding="utf-8") as f:
            f.write(r)
        os.startfile(fp)

    def save_raw_debug_to_file(self, debug_text_widget):
        import os
        import subprocess
        d = "gespeichert"
        if not os.path.exists(d):
            os.makedirs(d)
        today = time.strftime("%Y-%m-%d")
        for i in range(1, 100):
            fn = f"RawDebug_{today}_{i:02d}.txt"
            fp = os.path.join(d, fn)
            if not os.path.exists(fp):
                break
        header = f"Mobilfunkzellen-Analyzer v2.1.1 - RawData/Debug-Ausgabe {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        content = debug_text_widget.get("1.0", tk.END)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(header + content)
        os.startfile(fp)

    def load_settings(self):
        try:
            with open("config.txt", "r", encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines()]
                if len(lines) >= 2:
                    self.saved_port = lines[0]
                    self.saved_profile = int(lines[1])
                if len(lines) >= 3:
                    self.saved_orientation = (lines[2] == "1")
                self.loaded_log = lines[3].replace("|LINE|", "\n") if len(lines) >= 4 else ""
                self.loaded_hist = lines[4].replace("|LINE|", "\n") if len(lines) >= 5 else ""
                if len(lines) >= 8:
                    self.window_x = int(lines[5])
                    self.window_y = int(lines[6])
                    self.window_state = lines[7]
        except Exception as e:
            print(f"Fehler beim Laden: {e}")

    def on_closing(self):
        self.window_x = self.root.winfo_x()
        self.window_y = self.root.winfo_y()
        self.window_state = self.root.state()

        if self.window_state != "zoomed":
            self.window_x = self.root.winfo_x()
            self.window_y = self.root.winfo_y()

        self.running = False
        
        if self.last_cid is not None:
            elapsed = time.time() - self.cell_start_time
            dur = time.strftime('%H:%M:%S', time.gmtime(time.time() - self.cell_start_time))
            events_display = ""
            for ev, count in self.active_cell_events.items():
                if count == 1:
                    events_display += ev
                elif count > 1:
                    events_display += f"{count}{ev}"
            final_entry = f"{self.start_ts:<10} {self.last_lac:<8} {self.last_cid:<12} {self.current_max_dbm:<10} {dur} {events_display} ☒"
            self.history_data.insert(0, final_entry)
            self.active_cell_events = {}
            self.cell_table.delete('3.0', '4.0')
            self.cell_table.insert('3.0', final_entry + "\n")
            
            self.last_cid = None
            
        self.save_settings()
        
        if self.ser and self.ser.is_open:
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
        import os
        info_win = tk.Toplevel(self.root)
        info_win.title("Informationen")
        info_win.geometry("1000x600")
        
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cell-ID.ico")
        if os.path.exists(icon_path):
            info_win.iconbitmap(icon_path)
            
        txt = scrolledtext.ScrolledText(info_win, wrap=tk.WORD, font=("Arial", 10))
        txt.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        info_text = """Dieses Programm wird als nicht-kommerzielle Freeware zur Verfügung gestellt. Andere Nutzungen sind unter unten genannten Bedingungen erwerbbar.

(C) 2026 - Cell-ID: Mobilfunkzellen-Analyzer Version 2.1.2 - Entwickelt von  M. Trojan, Trojanix Lab int.

Programmbeschreibung und Kompatibilität
Das Programm ist für den Betrieb mit Mobilfunkmodems konzipiert (z. B. Ericsson, Dell, Huawei, Sierra, Telit, Quectel, Gemalto). 
Die Kompatibilität umfasst im PC verbaute Module sowie über USB verbundene Endgeräte wie Handys oder Tablets, sofern diese einen seriellen Kommunikationsanschluss zur Verfügung stellen.

BEDIENUNGSANLEITUNG:

-----------------------------------------------------------------

Raw/Debug. & Terminal-Funktionen

- Raw/Debug.: Öffnet das Analyse-Terminal für den direkten Datenaustausch mit der Modem-Hardware.
- RawData: Anzeige des ungefilterten Datenstroms (AT-Befehle und deren Antworten). Über die Eingabezeile können eigene AT-Befehle manuell an das Modem gesendet werden.
- DEBUG (Hersteller-Support-Check): Automatische Prüfung des Modems auf unterstützte herstellerspezifische Diagnose-Befehlssätze, um das Analyse-Potenzial der Hardware zu ermitteln.
- Log löschen: Entfernt den gesamten Textinhalt aus dem aktuellen Terminal-Fenster.
- Log kopieren: Schreibt den Inhalt des Terminal-Fensters in die Zwischenablage.
- Log Speichern: Exportiert den Debug-Log als Textdatei (RawDebug_...) in den Ordner "gespeichert" und öffnet die Datei sofort zur Ansicht.

Steuerungs-Elemente

- Ansicht (H/V): Wechselt zwischen horizontalem und vertikalem GUI-Layout.
- Eingabe des COM-Ports: Auswahl der seriellen Schnittstelle des Modems.
- START: Baut die serielle Verbindung zum Modem auf und beginnt mit der Datenabfrage.
- STOPP: Trennt die Verbindung zum Modem sicher.
- Reset: Löscht die historischen Daten und setzt die Zähler für ein neues Log zurück.
- Kopieren: Speichert die aktuelle Historie der Funkzellen-Wechsel in die Zwischenablage.
- Speichern: Erstellt einen vollständigen Snapshot der GUI als Bericht-Textdatei (Bericht_...) im Ordner "gespeichert" und öffnet diese sofort.
- Profil: Wahl des Treibers/Befehlssatzes (z.B. Qualcomm/Intel/Huawei), um die korrekte Interpretation der Modem-Antworten sicherzustellen.

Netz- & Gerätestatus

- Signalstärke-Nadel: Grafische Visualisierung des RSSI-Pegels (Empfangsstärke).
- Status: Zeigt an, ob das Gerät im Heimatnetz, im Roaming oder offline ist.
- Signal: Der absolute Empfangspegel der aktiven Zelle in dBm.
- Cell-ID: Eindeutige Kennung der Funkzelle innerhalb eines Netzgebiets.
- LAC: Local Area Code zur Identifikation des Standortbereichs.
- Typ: Die genutzte Mobilfunktechnologie (z.B. LTE, 5G, UMTS).
- Frequenz: Die Betriebsfrequenzen des Modems für den Download (Downlink) und Upload (Uplink).
- Bandbreite: Die Breite des genutzten Frequenzkanals (z.B. 10 MHz oder 20 MHz bei LTE).
- MCC: Mobile Country Code (Ländercode, z.B. 262 für Deutschland).
- MNC: Mobile Network Code (Anbieterkennung, z.B. 01 für Telekom).
- Betreiber: Name des Mobilfunkanbieters.

SIM-Karte & Geräte-Informationen

- Nummer: Die fest auf der SIM-Karte hinterlegte Rufnummer (MSISDN).
- IMSI: International Mobile Subscriber Identity (eindeutige Identität des SIM-Nutzers).
- ICCID: Eindeutige Seriennummer der physischen SIM-Karte.
- IMEI: Eindeutige Seriennummer des Modems/Geräts.
- Gerät: Hersteller und Modellbezeichnung des Modems.
- Firmwareversion: Die aktuelle Software-Revision des Modems.

Analyse-Fenster

- Funkzellen-Historie: Protokoll über alle durchgeführten Zellwechsel inkl. Zeitstempel und Signalpegel.
  Eingehende Anrufe und Nachrichten werden mit ☏ bzw. ✉ hinter der Zeile und Programmbeendigung mit ☒ ergänzt. 
- System-Log: Zentrales Protokoll für Systemereignisse, Anrufe, SMS und technische Fehlermeldungen.

- Mobilfunk-Vorgaben: Vom Netz übermittelte Konfigurationsparameter für das Gerät:
  - RACH: Random Access Channel - Leistungssteigerung des Gerätes bei Fehler (Power Ramping Step).
  - PUSCH: (P0_Pusch) Physical Uplink Shared Channel - Ziel-Sendeleistungs-Anpassung des Gerätes.
  - P.Step: Power Step - Schrittweite der Sendeleistungsanpassung.
  - Max.ReTX: Maximale Anzahl an Wiederholungsversuchen bei Übertragungsfehlern.
  - Sicherheit: Die aktive Verschlüsselungs-Methode der Funkverbindung.

Umgebungsanalyse

- Funkzellen in Reichweite: Liste aller Nachbarzellen, die vom Modem empfangen werden:
  - Band: Das genutzte Frequenzband der Zelle.
  - Kanal: Die exakte Kanalnummer (ARFCN/EARFCN).
  - PCI: Physical Cell Identity (Kennung der Nachbarzelle).
  - RSSI: Die Empfangsstärke dieser spezifischen Zelle.

-----------------------------------------------------------------

Anruferfenster

- Signalisiert, dass ein eingehender Anruf eingeht. Dabei wird die Datei Ring.wav abgespielt. Die 3 Optionen stehen dann zu Verfügung: Annehmen, Ablehnen (abweisen) oder Ignorieren (Fenster schließen). Auch ein verpasster Anruf wird in die System-Log eingetragen.

-----------------------------------------------------------------

Datenverarbeitung

Bei Schließen des Programms werden alle Daten aus Funkzellen-Historie und System-Log automatisch gespeichert (wie Ansicht, Profil und COM ebenfalls in die "config.txt) und beim nächsten Programmstart wieder geladen. 
Alte Daten wird man los, indem man vor dem Schließen "Reset" wählt und das Programm schließt - Ansicht, Profil und COM-Einstellungen gehen dabei nicht verloren.

-----------------------------------------------------------------

Netztyp		Kanal		Frequenzbereich
LTE 5G		9210-9659		700 MHz
LTE-20		6150-6449		800 MHz
P-GSM		0-124		900 MHz
E-GSM		975-1023		900 MHz
UMTS 3G		2937-3088		900 MHz
LTE-8		3450-3799		900 MHz
UMTS		3257-4458		950 MHz
LTE-3		1200-1949		1800 MHz
GSM		512-885		1800 MHz
UMTS		10562-10838		2100 MHz
UMTS		0-599		2100 MHz
LTE-7		2400-2649		2600 MHz

-----------------------------------------------------------------

Die Netzbetreiber ändern sich alle paar Jahre, weshalb die Zuordnung der MNC zu einem Netzbetreiber von diesem Programm wie folgt interpretiert wird und sich jederzeit wieder ändern kann (Stand Februar 2026, Angaben ohne Gewähr):

01 und 06:		D1-Netz, Vorwahlen: 0151, 0160, 0170, 0171, 0175
		Telekom (seit 2002)
		ehem. DeTeMobil (1992-2002)
02:		D2-Netz, Vorwahlen: 0172, 0173, 0174
		Vodafone (seit 2000)
		ehem. Mannesmann (1990-2000)
04 und 09:		D2-Netz, Vorwahlen: 0152, 0162, 0172, 0173, 0174
		Vodafone (seit 2000)
03 und 05:		Vorwahlen: 0157, 0163, 0177, 0178
		Telefónica (seit 2014)
		ehem. BASE (2005-2014)
		ehem. KPN (2000-2005)
		ehem. E-Plus (1993-2000)
07, 08 und 11:		Vorwahlen: 0159, 0176, 0179
		Telefónica (seit 2005)
		ehem. O2 (2002-2005)
		ehem. BT Group (2000-2002)
		ehem. Viag Interkom (1995–2000)
10:		Quam (2000-2002, Telefónica)
60:		DBInfraGo AG (Bahn AG, bis 1994 Deutsche Bundesbahn)
13:		BAAINBw (Bundesamt für Ausrüstung, Informationstechnik 
		und Nutzung der Bundeswehr, Bw-eigenes Netz)
14:		Lebara Limited
15:		Airdata (Industrie-Datendienste)
22:		Sipgate Wireless
23:		Vorwahl: 01556
		1&1
43:		Lycamobile
72 und 74:		Ericsson (Test und Forschung)
73: 		Nokia (Test und Forschung)
78: 		T-Mobile (Telekom-intern und Test)
98: 		nicht öffentlich (BNetzA: BOS, Geheime Regierungsnetze)


-----------------------------------------------------------------

GSM-Verschlüsselungsmodi (A5)

A5/0: Keine Verschlüsselung. Die übertragenen Daten sind im Klartext und für jeden mit einem entsprechenden Empfänger im Umkreis mitlesbar.
A5/1: Veralteter GSM-Standard. Ursprünglich für Europa entworfen, aufgrund geringer Schlüssellängen heute unsicher und kann in Echtzeit geknackt werden.
A5/2: Geschwächte Export-Variante. Entwickelt, um die Sicherheit für den Export in bestimmte Länder künstlich zu schwächen; noch leichter zu knacken als A5/1.
A5/3 (KASUMI): Aktueller, sicherheitsgeprüfter Standard. Basiert auf dem Blockchiffre KASUMI und bietet Schutz gegen moderne Kryptoanalysen.
A5/4: Modern. Verbesserte Implementierung innerhalb der A5-Reihe, die eine höhere Widerstandsfähigkeit gegen Angriffe bietet.
A5/5: Modern. Aktueller Stand der A5-Verschlüsselung für GSM-Netze zur Sicherstellung der Vertraulichkeit.

Moderne Verschlüsselungs-Algorithmen (LTE/5G)

0 (KEIN): Entspricht dem A5/0-Modus. Es erfolgt keinerlei Verschlüsselung auf der Funkschnittstelle.
1 (SNOW): SNOW 3G ist ein stromchiffrierbasierter Algorithmus, der in UMTS und LTE zur Verschlüsselung von Daten und Integritätsschutz eingesetzt wird.
2 (AES): Advanced Encryption Standard (128-Bit). Internationaler Goldstandard. Er ist extrem recheneffizient und mathematisch hochgradig sicher.
3 (ZUC): Ein moderner, leistungsstarker Stromchiffrier-Algorithmus (ZUC-Chiffre), der speziell für 4G/LTE- und 5G-Netzwerke entwickelt wurde und sicher ist.

-----------------------------------------------------------------


CREDITS & RECHTLICHE HINWEISE

Entwickler: Mehmet S. Trojan - Trojanix Lab int., Copyright 2026

Lizenz: Dieses Programm wird als Freeware zur Verfügung gestellt. Die Nutzung ist ausschließlich auf den privaten Bereich beschränkt. Eine kommerzielle Nutzung ist erst nach Entrichtung einer entsprechenden Gebühr gestattet. Konditionen und Abwicklung unter: m-trojan@mail.ru

Haftungsausschluss:
Die Nutzung der Software erfolgt ausdrücklich auf eigene Gefahr. Der Entwickler übernimmt keinerlei Haftung für direkte oder indirekte Schäden, die durch eine unsachgemäße Behandlung des Programms oder der verwendeten Hardware (PC, Modem, Mobilfunkendgeräte) entstehen. Dies gilt insbesondere für Fehlfunktionen oder Hardwaredefekte, die durch die manuelle Eingabe von Steuerbefehlen über das Diagnose-Terminal hervorgerufen werden könnten. Ein Anspruch auf Schadersatz bei Datenverlust oder Folgeschäden am Betriebssystem oder der Hardware ist ausgeschlossen."""
        
        txt.insert(tk.INSERT, info_text)
        txt.configure(state='disabled')
        
        tk.Button(info_win, text="Schließen", command=info_win.destroy).pack(pady=5)

    def setup_gui(self):
        top_frame = tk.Frame(self.root, bg="#34495e", pady=10)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.btn_debug = tk.Button(top_frame, text="Raw/Debug", command=self.show_debug_window, bg="#e67e22", fg="white", font=("Arial", 10, "bold"))
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

        self.btn_reset = tk.Button(top_frame, text="Reset", command=self.reset_logs, bg="#7f8c8d", fg="white", width=10, font=("Arial", 10, "bold"))
        self.btn_reset.pack(side=tk.LEFT, padx=5)

        self.btn_copy = tk.Button(top_frame, text="Kopieren", command=self.copy_history, bg="#2980b9", fg="white", width=10, font=("Arial", 10, "bold"))
        self.btn_copy.pack(side=tk.LEFT, padx=5)

        tk.Button(top_frame, text="Speichern", command=self.save_report_to_file, bg="#27aeff", fg="white", width=10, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        self.btn_profile = tk.Button(top_frame, text="Profil:", command=self.switch_profile, bg="black", fg="#f1c40f", width=8, font=("Arial", 10, "bold"))
        self.btn_profile.pack(side=tk.LEFT, padx=5)

        if hasattr(self, 'saved_profile'):
            self.current_profile_idx = self.saved_profile
            cmd, name = self.cmd_profiles[self.current_profile_idx]
            self.lbl_profile_name = tk.Label(top_frame, text=f"{name}", bg="#34495e", fg="#f1c40f", font=("Arial", 10, "bold"))
        else:
            self.lbl_profile_name = tk.Label(top_frame, text="Allgemein Mobile", bg="#34495e", fg="#f1c40f", font=("Arial", 10, "bold"))
        
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
        self.system_log.tag_config("gelb", foreground="#f1c40f")
        self.apply_layout()

        self.apply_layout() 
        
        if hasattr(self, 'saved_orientation') and self.saved_orientation:
            self.is_vertical = False
            self.toggle_view()

        if hasattr(self, 'loaded_log') and self.loaded_log:
            self.system_log.insert("1.0", self.loaded_log)
            
        if hasattr(self, 'loaded_hist') and self.loaded_hist:
            self.cell_table.insert("1.0", self.loaded_hist)
            for line in self.loaded_hist.splitlines():
                if line.strip():
                    self.history_data.append(line.strip())

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
            self.hist_frame.place(relx=0, rely=0, relwidth=0.55, relheight=0.69)
            self.log_frame.place(relx=0, rely=0.70, relwidth=0.55, relheight=0.30)
            self.vorgaben_frame.place(relx=0.56, rely=0, relwidth=0.45, relheight=0.30)
            self.reichweite_frame.place(relx=0.56, rely=0.31, relwidth=0.45, relheight=0.69)

    def toggle_view(self):
        self.is_vertical = not self.is_vertical
        self.apply_layout()

    def handle_incoming_call(self, number="Unbekannt"):
        now = time.time()
        
        if now - self.last_finish_time < 15:
            return
        
        self.last_ring_time = now

        if self.call_active:
            if number != "Unbekannt" and self.call_number == "Unbekannt":
                self.call_number = number
                if self.call_window and self.call_window.winfo_exists():
                    self.lbl_call.config(text=number) 
            return 

        self.call_active = True
        self.call_number = number
        if not self.call_logged:
            self.sys_log("Ereignis erfasst: ☎ Anruf ⤴")
            self.handle_event("☏")
            self.call_logged = True
        self.call_window = tk.Toplevel(self.root)
        self.call_window.title("  A N R U F  ☎")
        import os
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cell-ID.ico")
        if os.path.exists(icon_path):
            self.call_window.iconbitmap(icon_path)
        self.call_window.geometry("280x170")
        self.call_window.configure(bg="#8B0000")
        self.call_window.attributes("-topmost", True)

        w = 280
        h = 170

        self.root.update_idletasks()
        
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        pos_x = root_x + (root_width // 2) - (w // 2)
        pos_y = root_y + (root_height // 2) - (h // 2)

        self.call_window.geometry(f"{w}x{h}+{pos_x}+{pos_y}")

        self.lbl_call = tk.Label(
            self.call_window,
            text=number,
            font=("Arial", 18, "bold"),
            fg="white",
            bg="#8B0000"
        )
        self.lbl_call.pack(pady=15)
        
        btn_frame = tk.Frame(self.call_window, bg="#8B0000")
        btn_frame.pack(side="bottom", pady=10)

        tk.Button(
            btn_frame,
            text="Annehmen",
            width=9,
            command=self.answer_call,
            bg="#27ae60",
            fg="white"
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame,
            text="Ablehnen",
            width=9,
            command=self.reject_call,
            bg="#c0392b",
            fg="white"
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame,
            text="Ignorieren",
            width=9,
            command=self.close_call,
            bg="#7f8c8d",
            fg="white"
        ).pack(side="left", padx=4)

        if self.call_timer:
            self.root.after_cancel(self.call_timer)

        self.call_timer = self.root.after(1000, self.check_call_timeout)

        try:
            import winsound
            import os
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Ring.wav")
            winsound.PlaySound(p, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)
        except:
            pass

    def finish_call(self):

        if not self.call_active:
            return

        if self.call_window and self.call_window.winfo_exists():
            self.call_window.destroy()
            self.call_window = None

        status = self.call_status if self.call_status else "verpasst"
        dauer = ""

        if self.call_start_time and status == "angenommen":
            elapsed = int(time.time() - self.call_start_time)
            dauer = " (" + time.strftime("%M:%S", time.gmtime(elapsed)) + ")"
        time_str = time.strftime("%H:%M:%S")
        cid = self.lbl_cid_top.cget("text").replace("Cell-ID: ", "")

        log_text = f"[{time_str}] ☎ Anruf von {self.call_number} (CID: {cid}) → {status}{dauer}\n"
        self.system_log.insert("1.0", log_text, "gelb")

        self.last_finish_time = time.time()

        self.call_active = False
        self.call_number = None
        self.call_status = None
        self.call_logged = False
        self.clip_received = False
        self.call_ignored = False
        self.call_start_time = None

    def answer_call(self):
        if self.ser:
            self.ser.write(b'ATA\r')
            self.call_status = "angenommen"
            self.call_start_time = time.time()

    def reject_call(self):
        if self.ser:
            self.ser.write(b'ATH\r')

    def answer_call(self):

        if self.ser:
            self.ser.write(b'ATA\r')

        self.call_status = "angenommen"
        self.finish_call()

    def reject_call(self):

        if self.ser:
            self.ser.write(b'ATH\r')

        self.call_status = "abgelehnt"
        self.finish_call()

    def close_call(self):

        self.call_status = "ignoriert"
        self.call_ignored = True
        self.finish_call()

    def check_call_timeout(self):

        if time.time() - self.last_ring_time > 15:
            self.call_status = "verpasst"

            self.finish_call()

            if self.call_window and self.call_window.winfo_exists():
                self.call_window.destroy()

            self.call_active = False
            self.call_number = None
            self.call_log_index = None

        else:
            self.call_timer = self.root.after(1000, self.check_call_timeout)

    def fetch_and_log_sms(self, index):
        self.ser.write(f'AT+CMGR={index}\r'.encode())
        time.sleep(0.5)
        raw_response = self.ser.read_all().decode(errors='ignore')
    
        num_match = re.search(r'\+CMGR:.*?"(\+?\d+)"', raw_response)
        absender = num_match.group(1) if num_match else "Unbekannt"
    
        cid = self.lbl_cid_top.cget("text").replace("Cell-ID: ", "")
        time_str = time.strftime("%H:%M:%S")
        sms_line = f"[{time_str}] ✉ Nachricht via CID {cid} → empfangen"
        
        self.system_log.tag_config("gelb", foreground="#f1c40f")
        
        self.system_log.insert("1.0", sms_line, "gelb")

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
        header = f"{'RACH':<8} {'PUSCH':<8} {'P.Step':<8} {'Max.ReTX':<10} {'Sicherheit'}\n"
        sep = "-" * 50 + "\n"
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
            "A5/0": ("⚠ A5/0 KEIN ⚠", "warn"),
            "A5/1": ("⚠ A5/1 Veraltet", "warn"),
            "A5/2": ("⚠ A5/2 Geschwächt", "warn"),
            "A5/3": ("🔒 A5/3 Aktuell", "normal"),
            "A5/4": ("🔒 A5/4 Modern", "normal"),
            "A5/5": ("🔒 A5/5 Modern", "normal"),
            "0": ("⚠ 0: KEIN ⚠", "warn"),
            "1": ("🔒 1: SNOW", "normal"),
            "2": ("🔒 2: AES", "normal"),
            "3": ("🔒 3 ZUC", "normal")
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
                matches = re.findall(r'arfcn[:=]\s*(\d+).*?pci[:=]\s*(\d+).*?(-?\d+)\s*dBm', raw_data, re.IGNORECASE)
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
            
    def handle_event(self, event_type):
        if event_type not in self.active_cell_events:
            self.active_cell_events[event_type] = 0

        self.active_cell_events[event_type] += 1

        events_display = ""

        for ev, count in self.active_cell_events.items():
            if count == 1:
                events_display += ev
            elif count > 1:
                events_display += f"{count}{ev}"

        self.lbl_status.config(text=f"Status: Aktiv {events_display}")

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
                time.sleep(0.2)
                self.ser.write(b'AT+CLIP=1\r')
                time.sleep(0.2)
                self.ser.write(b'AT+CRC=1\r')
                time.sleep(0.5)
                self.ser.write(b'AT+CLIP=1\r')
                time.sleep(0.2)

                header_text = "Uhrzeit"
                self.history_data = [line for line in self.history_data if header_text not in line and "---" not in line]
                self.cell_table.delete('1.0', tk.END)
                header = f"{'Uhrzeit':<10} {'LAC':<8} {'Cell-ID':<12} {'dBm (max)':<10} {'Status'}\n" + "-"*60 + "\n"
                self.cell_table.insert(tk.END, header)
                for entry in self.history_data:
                    self.cell_table.insert(tk.END, entry + "\n")

                self.sys_log("Starte Live-Update...")
                self.running = True
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

                    if "+CLIP:" in res_csq:

                        match = re.search(r'\+CLIP:\s*"([^"]+)"', res_csq)
                        number = match.group(1) if match else "Unbekannt"

                        self.handle_incoming_call(number=number)

                        self.clip_received = True

                    elif "RING" in res_csq:

                        if self.call_active or self.call_ignored:
                            return

                        self.handle_incoming_call(number="Unbekannt")

                        if not self.call_logged:
                            self.last_ring_time = time.time()
                    
                    if "+CMTI:" in res_csq:
                        self.handle_event("✉")

                    res_srv = res_csq.strip()
                    
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
                        try:
                            self.ser.write(b'AT*EMONITOR\r')
                            time.sleep(0.4)
                            res_nei = self.ser.read_all().decode(errors='ignore')

                            if res_nei:
                                self.update_neighbors(res_nei)

                        except:
                            pass
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
                            if stat_code != getattr(self, 'last_net_status', None):
                                self.last_net_status = stat_code
                                status_text = status_map[stat_code][0]
                                
                                operator_name = self.mnc_dict.get(net_code[3:], 'Unbekannt')
                                
                                time_str = time.strftime("%H:%M:%S")
                                log_entry = f"[{time_str}] Netz-Status: {status_text} ({operator_name})\n"
                                
                                self.system_log.insert("1.0", log_entry, "white")
                                self.system_log.tag_config("white", foreground="white")
                            txt, color = status_map.get(stat_code, ("Unbekannt", "#7f8c8d"))
                            self.lbl_status.config(text=f"Status: {txt}", fg=color)

                            if reg_match.group(2) and reg_match.group(3):
                                l_dec, c_dec = int(reg_match.group(2), 16), int(reg_match.group(3), 16)
                                self.lbl_lac_top.config(text=f"LAC: {l_dec}")
                                self.lbl_cid_top.config(text=f"Cell-ID: {c_dec}")
                                
                                if c_dec != self.last_cid:
                                    if self.last_cid is not None:
                                        dur = time.strftime('%H:%M:%S', time.gmtime(time.time() - self.cell_start_time))
                                        events_display = ""
                                        for ev, count in self.active_cell_events.items():
                                            if count == 1:
                                                events_display += ev
                                            elif count > 1:
                                                events_display += f"{count}{ev}"
                                        log_entry = f"{self.start_ts:<10} {self.last_lac:<8} {self.last_cid:<12} {self.current_max_dbm:<10} {dur} {events_display}"
                                        self.history_data.insert(0, log_entry)
                                        self.active_cell_events = {}
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
                        operator_name = self.mnc_dict.get(net_code[3:])
                        if not operator_name:
                            operator_name = self.detected_operator_from_modem 
                        if not operator_name:
                            operator_name = "Unbekannt" 
                        self.lbl_oper.config(text=f"Betreiber: {operator_name}")
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
        import os
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cell-ID.ico")
        if os.path.exists(icon_path):
            debug_win.iconbitmap(icon_path)
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
        tk.Button(btn_frame, text="Log kopieren", command=lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self.debug_text_widget.get("1.0", tk.END))), bg="#2c3e50", fg="white", width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Log speichern", command=lambda: self.save_raw_debug_to_file(self.debug_text_widget), bg="#27aeff", fg="white", width=15).pack(side=tk.LEFT, padx=5)

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