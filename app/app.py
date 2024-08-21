import sys
import threading
import psutil
import socket
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QMenuBar,
    QAction, QStatusBar, QHBoxLayout, QFrame, QScrollArea, QRadioButton,
    QButtonGroup, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot
from scapy.all import sniff, IP , IP_PROTOS

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize selected interface variable
        self.selected_interface = None

        # Initialize pause attribute
        self.paused = False

        # Set up the main window
        self.setWindowTitle("Windows Sniffer App")
        self.setGeometry(100, 100, 1024, 768)
        self.setStyleSheet("background-color: #333333; color: #FFFFFF; font-family: Arial, sans-serif;")

        # Initialize the main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        # Create menu bar
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)
        self.menu_bar.setStyleSheet("background-color: #444444; color: #FFFFFF; padding: 5px;")

        # File Menu
        file_menu = self.menu_bar.addMenu("File")
        file_menu.setStyleSheet("padding: 5px;")
        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        export_csv_action = QAction("Export as CSV", self)
        export_csv_action.triggered.connect(self.export_as_csv)
        file_menu.addAction(export_csv_action)
        export_json_action = QAction("Export as JSON", self)
        export_json_action.triggered.connect(self.export_as_json)
        file_menu.addAction(export_json_action)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Documentation Menu
        documentation_menu = self.menu_bar.addMenu("Documentation")
        documentation_menu.setStyleSheet("padding: 5px;")
        docs_action = QAction("Open Documentation", self)
        docs_action.triggered.connect(self.open_documentation)
        documentation_menu.addAction(docs_action)

        # Add Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("background-color: #444444; color: #FFFFFF; padding: 5px;")

        # Add header and next button layout
        self.setup_header()

        # Add Network Interfaces List
        self.setup_interface_list()

    def setup_header(self):
        # Create a horizontal layout for the header
        header_layout = QHBoxLayout()

        # Header Label
        self.header_label = QLabel("Select Network Interface", self)
        self.header_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        self.header_label.setAlignment(Qt.AlignLeft)

        # Next Button
        self.next_button = QPushButton("Next →", self)
        self.next_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #555555; color: #FFFFFF;")
        self.next_button.clicked.connect(self.go_to_next_page)
        self.next_button.setFixedSize(100, 40)

        # Add widgets to the header layout
        header_layout.addWidget(self.header_label)
        header_layout.addWidget(self.next_button, alignment=Qt.AlignRight)

        # Add the header layout to the main layout
        self.main_layout.addLayout(header_layout)

    def setup_interface_list(self):
        # Create a scroll area for the interface list
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("""
            QScrollBar:vertical {
                border: 1px solid #555555;
                background: #333333;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #777777;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical {
                border: 1px solid #555555;
                background: #333333;
                height: 0px;
            }
            QScrollBar::sub-line:vertical {
                border: 1px solid #555555;
                background: #333333;
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #333333;
            }
        """)

        # Create a container widget for the scroll area
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_area.setWidget(scroll_content)

        # Add the scroll area to the main layout
        self.main_layout.addWidget(scroll_area)

        # Button group for selecting interfaces
        self.interface_group = QButtonGroup()

        interfaces = psutil.net_if_addrs().items()

        for interface_name, interface_addresses in interfaces:
            interface_frame = QFrame()
            interface_frame.setStyleSheet("background-color: #444444; border-radius: 10px; margin: 10px; padding: 10px;")
            interface_layout = QHBoxLayout(interface_frame)

            # Radio button to select interface
            radio_button = QRadioButton(interface_name, self)
            radio_button.setStyleSheet("font-size: 18px; color: #FFFFFF;")
            self.interface_group.addButton(radio_button)
            interface_layout.addWidget(radio_button)

            # IP and MAC address labels
            for address in interface_addresses:
                if address.family == socket.AF_INET:
                    ip_label = QLabel(f"IP: {address.address}", self)
                    ip_label.setStyleSheet("font-size: 16px; color: #AAAAAA; margin-left: 20px;")
                    interface_layout.addWidget(ip_label)
                elif address.family == psutil.AF_LINK:
                    mac_label = QLabel(f"MAC: {address.address}", self)
                    mac_label.setStyleSheet("font-size: 16px; color: #AAAAAA; margin-left: 20px;")
                    interface_layout.addWidget(mac_label)

            # Add the frame to the scrollable layout
            scroll_layout.addWidget(interface_frame)

        # Status Bar update example
        self.status_bar.showMessage("Monitoring network interfaces.")

    def go_to_next_page(self):
        # Get the selected interface
        selected_button = self.interface_group.checkedButton()
        if selected_button:
            self.selected_interface = selected_button.text()
            print(f"Selected Interface: {self.selected_interface}")
            # Proceed to the next page
            self.show_next_page()
        else:
            self.status_bar.showMessage("Please select an interface before proceeding.")

    def show_next_page(self):
        # Remove and delete the current central widget
        if self.central_widget is not None:
            self.central_widget.setParent(None)

        # Create a QTabWidget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Style the tabs
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                background: #008080;
                color: #FFFFFF;
                padding: 10px 30px;
                font-size: 16px;
                min-width: 150px;
            }
            QTabBar::tab:selected {
                background: #663399;
            }
            QTabBar::tab:hover {
                background: #663399;
            }
            QTabWidget::pane {
                border: 1px solid #444444;
            }
        """)

        # Create tabs for each section
        self.add_sniffer_tab()
        self.add_tab("Recon", "#333333")
        self.add_tab("Services", "#333333")
        self.add_tab("Wireless", "#333333")
        self.add_tab("Visualization", "#333333")
        self.add_tab("Logs", "#333333")
        self.add_tab("Packet Crafter ", "#333333")

    def add_sniffer_tab(self):
        # Create a new QWidget for the Sniffer tab
        sniffer_tab = QWidget()
        layout = QVBoxLayout(sniffer_tab)

        # Create a QTableWidget to display captured packets
        self.sniffer_table = QTableWidget(sniffer_tab)
        self.sniffer_table.setColumnCount(6)  # Number of columns 
        self.sniffer_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Length" , "Source Port" , "Destination Port"])

        # Set column width to fit the table
        self.sniffer_table.horizontalHeader().setStretchLastSection(True)
        self.sniffer_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Customize header color
        self.sniffer_table.horizontalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #50C878;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #444444;
            }
        """)
        self.sniffer_table.verticalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #50C878;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #444444;
            }
        """)
        self.sniffer_table.setStyleSheet("""
            QScrollBar:vertical {
                border: 1px solid #555555;
                background: #333333;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #777777;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical {
                border: 1px solid #555555;
                background: #333333;
                height: 0px;
            }
            QScrollBar::sub-line:vertical {
                border: 1px solid #555555;
                background: #333333;
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #333333;
            }
        """)    
        layout.addWidget(self.sniffer_table)

        # Add the pause/resume button
        self.pause_button = QPushButton("Pause", self)
        self.pause_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #555555; color: #FFFFFF;")
        self.pause_button.clicked.connect(self.toggle_pause)
        layout.addWidget(self.pause_button)

        # Add sniffer tab to the tabs widget
        self.tabs.addTab(sniffer_tab, "Sniffer")

        # Start the sniffing thread
        self.start_sniffing()

    def toggle_pause(self):
        if self.paused:
            self.paused = False
            self.pause_button.setText("Pause")
        else:
            self.paused = True
            self.pause_button.setText("Resume")

    def add_tab(self, title, color):
        tab = QWidget()
        tab.setStyleSheet(f"background-color: {color};")
        self.tabs.addTab(tab, title)

    def start_sniffing(self):
        sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniff_thread.start()

    def sniff_packets(self):
        sniff(iface=self.selected_interface, prn=self.packet_handler, store=False)

    def packet_handler(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            proto = IP_PROTOS.d[packet[IP].proto]
            length = len(packet)
            src_port = str(packet[proto.upper()].sport) if packet.haslayer(proto.upper()) else None 
            dst_port = str(packet[proto.upper()].dport) if packet.haslayer(proto.upper()) else None 
            # Use a signal-slot mechanism to update the table from the main thread
            QMetaObject.invokeMethod(
                self, "update_table",
                Qt.QueuedConnection,
                Q_ARG(str, src_ip),
                Q_ARG(str, dest_ip),
                Q_ARG(str, str(proto)),
                Q_ARG(str, str(length)),
                Q_ARG(str, src_port),
                Q_ARG(str, dst_port)
            )

    @pyqtSlot(str, str, str, str , str , str)
    def update_table(self, src_ip, dest_ip, proto, length , src_port , dst_port):
        if not self.paused:
            row_position = self.sniffer_table.rowCount()
            self.sniffer_table.insertRow(row_position)
            self.sniffer_table.setItem(row_position, 0, QTableWidgetItem(src_ip))
            self.sniffer_table.setItem(row_position, 1, QTableWidgetItem(dest_ip))
            self.sniffer_table.setItem(row_position, 2, QTableWidgetItem(proto))
            self.sniffer_table.setItem(row_position, 3, QTableWidgetItem(length))
            self.sniffer_table.setItem(row_position, 4, QTableWidgetItem(src_port))
            self.sniffer_table.setItem(row_position, 5, QTableWidgetItem(dst_port))


    def open_file(self):
        pass  # Placeholder for file open functionality

    def export_as_csv(self):
        pass  # Placeholder for export as CSV functionality

    def export_as_json(self):
        pass  # Placeholder for export as JSON functionality

    def open_documentation(self):
        webbrowser.open("https://your.documentation.url")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer_app = SnifferApp()
    sniffer_app.show()
    sys.exit(app.exec_())
