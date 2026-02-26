# Cell-ID 🇩🇪
📶 Professioneller Mobilfunknetzwerk-Analyzer. Visualisierung von Signalstärke, Zell-Historie und Netzparametern via AT-Kommandos. Unterstützt Multi-Vendor-Hardware zur Standortoptimierung und Sicherheitsanalyse von Funkzellen.

Dieses Programm wird als nicht-kommerzielle Freeware zur Verfügung gestellt. Andere Nutzungen sind unter unten genannten Bedingungen erwerbbar.

(C) 2026 - Cell-ID: Mobilfunkzellen-Analyzer von M. Trojan - Trojanix Lab int.

Professionelles Diagnose-Tool für WWAN-Schnittstellen und Mobilfunk-Infrastruktur

Der Mobile Network Analyzer ist eine Python-basierte Anwendung zur Echtzeit-Analyse von Mobilfunkverbindungen für 2G, 3G und 4G/LTE. Die Software agiert als Schnittstellen-Monitor, der über standardisierte und herstellerspezifische AT-Kommandos tiefgreifende Informationen aus den unteren Protokollschichten OSI-Layer 1 bis 3 extrahiert und visualisiert.

KERNFUNKTIONEN

Das System bietet ein Echtzeit-Signalmonitoring zur hochpräzisen Erfassung von Signalstärke in dBm sowie Qualitätsparametern wie RSRP, RSRQ und RSSI über ein analoges Visualisierungsinstrument. Die Layer-3 Analyse ermöglicht eine vollständige Identifikation von Funkzellen durch die Extraktion von MCC, MNC, LAC/TAC und der Cell-ID. Ein integriertes Sicherheits-Audit zur Überwachung der Luftschnittstellen-Verschlüsselung dient der Detektion unverschlüsselter Verbindungen und warnt vor potenziellen IMSI-Catchern. Die Zell-Historie mit Event-Logging erfasst chronologisch alle Zellwechsel zur Analyse der Netzstabilität und Erstellung von Bewegungsprofilen. Eine breite herstellerübergreifende Kompatibilität gewährleistet die Unterstützung spezialisierter Diagnoseprofile für Hardware von Sierra Wireless, Qualcomm, Huawei, Ericsson, Intel, Telit und weiteren Anbietern. Zudem erlaubt ein Nachbarzellen-Scanner die Überwachung benachbarter Funkzellen zur Identifikation der lokalen Netztopologie und Vorbereitung für Triangulations-Verfahren.

TECHNISCHER NUTZEN

Das Programm unterstützt die Standort-Optimierung durch die exakte Ausrichtung von Richtantennen mittels Echtzeit-Pegelmessung. In der Fehlerdiagnose ermöglicht es die Identifikation von Verbindungsabbrüchen auf Protokollebene über das Extended Error Reporting. Für forensische Zwecke erlaubt die Software eine Überprüfung der Netzwerk-Integrität sowie die Erkennung von anomalen Basisstationen. Im Bereich Hardware-Benchmarking lässt sich die Empfangsleistung verschiedener WWAN-Module unter identischen Bedingungen objektiv vergleichen.

SYSTEMVORAUSSETZUNGEN UND ARCHITEKTUR

Die Software ist für das Betriebssystem Windows konzipiert und wurde erfolgreich auf den Versionen 7, 10 und 11 getestet. Die Kommunikation erfolgt über die serielle Schnittstelle via Serial-over-USB unter Verwendung von pyserial. Das System ist konform zu den Standards 3GPP TS 27.007, TS 27.005 sowie ITU-T V.250. Das leichtgewichtige GUI-Backend basiert auf dem Tkinter-Framework und kommt ohne schwere externe Abhängigkeiten aus.

ANWENDUNGSHINWEIS

Dieses Tool ist für technische Experten, Netzwerkadministratoren und Sicherheitsanalysten konzipiert. Es erfordert exklusiven Zugriff auf den Diagnose-Port des verwendeten WWAN-Modems.

BEDIENUNGSANLEITUNG

Programmbeschreibung und Kompatibilität
Die Software dient der technischen Analyse von Mobilfunkzellen und wird über eine grafische Benutzeroberfläche gesteuert. Die Kompatibilität umfasst im PC verbaute Module sowie über USB verbundene Endgeräte wie Handys oder Tablets, sofern diese einen seriellen Kommunikationsanschluss zur Verfügung stellen.

Ermittlung des COM-Ports
Die Identifikation des Kommunikationsanschlusses erfolgt manuell über das Betriebssystem. Unter Windows wird im Geräte-Manager unter Anschlüsse (COM & LPT) die Portnummer des Modems ermittelt. Handys oder Tablets müssen im Modem- oder Diagnosemodus verbunden sein, um als COM-Port gelistet zu werden. Im Programm wird der Port über das Dropdown-Menü gewählt. Die Liste basiert auf den beim Programmstart verfügbaren Systemressourcen. Der richtige COM-Port ist in der Regel gewählt, wenn nach dem Verbinden eine ICCID angezeigt wird.

Bedienoberfläche und Funktionen
Die Schaltfläche Verbinden initiiert die serielle Kommunikation mit dem gewählten Port und Profil, wobei die Einstellungen nach dem Beenden gespeichert werden. Über Ansicht wechseln kann das GUI-Layout zwischen einer vertikalen und einer horizontalen Darstellung umgeschaltet werden. Die Echtzeit-Anzeige visualisiert Technologie, Kanal, PCI, Signalstärke sowie Netzwerkparameter der aktiven Zelle. Die Zellhistorie protokolliert chronologisch alle Zellwechsel mit Kanalnummer und Maximalpegel. Die Reichweiten-Tabelle listet alle identifizierbaren Zellen in der Umgebung auf, wobei die aktive Verbindung türkisfarben hervorgehoben und Nachbarzellen grau dargestellt werden.

Funktionen der Schaltfläche Raw/Diag.
Diese Schaltfläche öffnet das erweiterte Analyse-Terminal zur direkten Interaktion mit der Hardware. Das Live-Log zeigt den ungefilterten Datenaustausch zwischen Software und Modem. Über die manuelle Befehlseingabe können spezifische AT-Befehle gesendet werden, um Antworten jenseits der Automatik zu provozieren. Die DEBUG-Funktion dient als Hersteller-Support-Check zur Identifikation des Befehlssatzes. Hierbei wird eine umfassende Liste herstellerspezifischer Diagnosebefehle für Plattformen wie Qualcomm, Intel, MediaTek oder HiSilicon abgearbeitet. Das Programm prüft bei jedem Befehl die Unterstützung durch die Hardware, was dem Anwender eine exakte Bestimmung der verfügbaren Diagnosedaten ermöglicht. Die Log-Verwaltung erlaubt das Leeren des Textbereichs oder das Kopieren des Scan-Ergebnisses.

CREDITS UND RECHTLICHE HINWEISE

Lizenz
Die Nutzung ist ausschließlich auf den privaten Bereich beschränkt. Eine kommerzielle Nutzung ist erst nach Entrichtung einer entsprechenden Gebühr gestattet. Konditionen und Abwicklung können über m-trojan@mail.ru angefragt werden.

Haftungsausschluss
Die Nutzung der Software erfolgt ausdrücklich auf eigene Gefahr. Der Entwickler übernimmt keinerlei Haftung für direkte oder indirekte Schäden, die durch eine unsachgemäße Behandlung des Programms oder der verwendeten Hardware entstehen. Dies gilt insbesondere für Fehlfunktionen oder Hardwaredefekte, die durch die manuelle Eingabe von Steuerbefehlen über das Diagnose-Terminal hervorgerufen werden könnten. Ein Anspruch auf Schadenersatz bei Datenverlust oder Folgeschäden am Betriebssystem oder der Hardware ist ausgeschlossen.
