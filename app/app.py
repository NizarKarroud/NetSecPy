import sys
import psutil
import socket
import webbrowser
from recon.host import Scanner
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QMenuBar,
    QAction, QStatusBar, QHBoxLayout, QFrame, QScrollArea, QRadioButton,
    QButtonGroup, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView , QLineEdit , QStackedWidget , QGridLayout
)
from PyQt5.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot
from scapy.all import AsyncSniffer, IP , IP_PROTOS ,  wrpcap, rdpcap , sniff
from scapy.plist import PacketList
from PyQt5.QtGui import QIcon
import os
import pyshark
import threading

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.stop_sniffing = threading.Event()  # Create an Event object for stopping pyshark sniffer

        # Initialize selected interface variable
        self.selected_interface = None

        # Initialize pause attribute
        self.paused = False

        self.setWindowTitle("Windows Sniffer App")
        self.setGeometry(100, 100, 1024, 768)
        self.setStyleSheet("background-color: #2A363B; color: #FFFFFF; font-family: Arial, sans-serif;")

        # Initialize the main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        # Create menu bar
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)
        self.menu_bar.setStyleSheet("background-color: #2A363B; color: #FFFFFF; padding: 5px;border-bottom: 1px solid #000000;")

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
        self.status_bar.setStyleSheet("background-color: #2A363B; color: #FFFFFF; padding: 5px;")

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
        self.next_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #E84A5F; color: #FFFFFF;")
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
                background: #2A363B;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #777777;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical {
                border: 1px solid #555555;
                background: #2A363B;
                height: 0px;
            }
            QScrollBar::sub-line:vertical {
                border: 1px solid #555555;
                background: #2A363B;
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #2A363B;
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

        # Dictionary to store interface data
        self.interface_data = {}

        for interface_name, interface_addresses in interfaces:
            interface_frame = QFrame()
            interface_frame.setStyleSheet("background-color: #202C31; border-radius: 10px; margin: 10px; padding: 10px;")
            interface_layout = QHBoxLayout(interface_frame)

            # Radio button to select interface
            radio_button = QRadioButton(interface_name, self)
            radio_button.setStyleSheet("font-size: 18px; color: #FFFFFF;")
            self.interface_group.addButton(radio_button)
            interface_layout.addWidget(radio_button)

            # Initialize data storage
            ip_address = None
            mac_address = None

            # IP and MAC address labels
            for address in interface_addresses:
                if address.family == socket.AF_INET:
                    ip_address = address.address
                    ip_label = QLabel(f"IP: {ip_address}", self)
                    ip_label.setStyleSheet("font-size: 16px; color: #AAAAAA; margin-left: 20px;")
                    interface_layout.addWidget(ip_label)
                elif address.family == psutil.AF_LINK:
                    mac_address = address.address
                    mac_label = QLabel(f"MAC: {mac_address}", self)
                    mac_label.setStyleSheet("font-size: 16px; color: #AAAAAA; margin-left: 20px;")
                    interface_layout.addWidget(mac_label)

            # Save the interface data
            self.interface_data[interface_name] = {
                'ip': ip_address,
                'mac': mac_address,
                'netmask' : address.netmask
            }

            # Add the frame to the scrollable layout
            scroll_layout.addWidget(interface_frame)

        # Status Bar update example
        self.status_bar.showMessage("Monitoring network interfaces.")

    def go_to_next_page(self):
        # Get the selected interface
        selected_button = self.interface_group.checkedButton()
        if selected_button:
            self.selected_interface = selected_button.text()
            # Retrieve the IP and MAC for the selected interface
            self.selected_ip = self.interface_data[self.selected_interface]['ip']
            self.selected_mac = self.interface_data[self.selected_interface]['mac']
            self.selected_subent = self.interface_data[self.selected_interface]['netmask']
            
            self.scanner = Scanner(self.selected_mac.replace("-",":"), self.selected_ip ,self.selected_subent ) 
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
                background: #E84A5F;
                color: #FFFFFF;
                padding: 10px 30px;
                border: 2px solid #555555;
                border-radius: 1px;
                font-size: 16px;
                min-width: 150px;
            }
            QTabBar::tab:selected {
                background: #FF847C;
            }
            QTabBar::tab:hover {
                background: #FF847C;
            }
            QTabWidget::pane {
                border: 1px solid #444444;
            }
        """)

        # Create tabs for each section
        self.add_sniffer_tab()

        self.recon_tab = ReconTab(scanner=self.scanner)
        self.tabs.addTab(self.recon_tab, "Recon")
        
        self.add_tab("Services", "#2A363B")
        self.add_tab("Wireless", "#2A363B")
        self.add_tab("Visualization", "#2A363B")
        self.add_tab("Logs", "#2A363B")
        self.add_tab("Packet Crafter ", "#2A363B")

    def add_sniffer_tab(self):
        # Create a new QWidget for the Sniffer tab
        sniffer_tab = QWidget()
        layout = QVBoxLayout(sniffer_tab)

        # Add a horizontal layout for the filter input and button
        filter_layout = QHBoxLayout()

        # Create the QLineEdit for BPF filter input
        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter BPF filter...")
        self.filter_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #555555;
                border-radius: 15px;
                padding: 10px;
                background-color: #2A363B;
                color: #FFFFFF;
                font-size: 16px;
            }
        """)
        filter_layout.addWidget(self.filter_input)

        # Create the Apply Filter button
        self.apply_filter_button = QPushButton("Apply Filter", self)
        self.apply_filter_button.setStyleSheet("""
            QPushButton {
                border: 2px solid #202C31;
                border-radius: 15px;
                padding: 10px;
                background-color: #202C31;
                color: #FFFFFF;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #151D20 ;
            }
            QPushButton:pressed {
                background-color: #151D20;
            }
        """)
        filter_layout.addWidget(self.apply_filter_button)

        self.apply_filter_button.clicked.connect(lambda : self.apply_filters(self.filter_input.text()))

        # Add the filter layout to the main layout
        layout.addLayout(filter_layout)

        # Create a QTableWidget to display captured packets
        self.sniffer_table = QTableWidget(sniffer_tab)
        self.sniffer_table.setColumnCount(6)  # Number of columns 
        self.sniffer_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port"])

        # Set column width to fit the table
        self.sniffer_table.horizontalHeader().setStretchLastSection(True)
        self.sniffer_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Customize header color
        self.sniffer_table.horizontalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #99B898;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #444444;
            }
        """)
        self.sniffer_table.verticalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #99B898;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #444444;
            }
        """)
        self.sniffer_table.setStyleSheet("""
            QScrollBar:vertical {
                border: 1px solid #555555;
                background: #2A363B;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #777777;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical {
                border: 1px solid #555555;
                background: #2A363B;
                height: 0px;
            }
            QScrollBar::sub-line:vertical {
                border: 1px solid #555555;
                background: #2A363B;
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #2A363B;
            }
        """)    
        layout.addWidget(self.sniffer_table)

        # Add the pause/resume button
        self.pause_button = QPushButton("Pause", self)
        self.pause_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #202C31 ; color: #FFFFFF; ")
        self.pause_button.clicked.connect(self.toggle_pause)
        layout.addWidget(self.pause_button)

        # Add sniffer tab to the tabs widget
        self.tabs.addTab(sniffer_tab, "Sniffer")

        # Start the sniffing thread
        self.sniff_packets()

    def toggle_pause(self):
        if self.paused:
            self.paused = False
            self.sniff_packets(self.filter_input.text())
            self.pause_button.setText("Pause")
        else:
            self.paused = True
            self.stop()
            self.pause_button.setText("Resume")

    def add_tab(self, title, color):
        tab = QWidget()
        tab.setStyleSheet(f"background-color: {color};")
        self.tabs.addTab(tab, title)

    def sniff_packets(self , filter = None):
        self.stop_sniffing.clear() 
        if filter: 
            self.pyshark_sniffer = pyshark.LiveCapture(interface=self.selected_interface, display_filter=filter )
        else:

            self.pyshark_sniffer = pyshark.LiveCapture(interface=self.selected_interface, output_file="temp.pcap")

        self.sniff_instance = threading.Thread(target=self.sniffing_thread)
        self.sniff_instance.start()

    def sniffing_thread(self):
        try:
            for packet in self.pyshark_sniffer.sniff_continuously():
                if self.stop_sniffing.is_set():
                    break
                self.pyshark_packet_handler(packet)
        except Exception as e:
            print(f"Sniffing thread encountered an error: {e}")

    def pyshark_packet_handler(self , packet):
        if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            proto = IP_PROTOS.d.get(int(packet.ip.proto) , f"{packet.ip.proto}")
            length = len(packet)
            
            try:
                # Check if the protocol exists in the packet
                if hasattr(packet, proto):
                    layer = getattr(packet, proto)
                    
                    # Safely get srcport and dstport if they exist
                    src_port = str(getattr(layer, 'srcport', None)) if hasattr(layer, 'srcport') else None
                    dst_port = str(getattr(layer, 'dstport', None)) if hasattr(layer, 'dstport') else None

                else:
                    print(f"Protocol {proto} not found in packet.")
                    src_port = None
                    dst_port = None

            except Exception as e:
                src_port = None
                dst_port = None

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

    def apply_filters(self, filter):
        if filter :
            filter = filter.strip()
            try : 
                self.stop()
            except Exception  :
                pass

            self.sniffer_table.setRowCount(0)
            self.filtered_packets = []
            self.filtered_packets = [packet for packet in pyshark.FileCapture('temp.pcap', display_filter=filter) ]
            print(self.filtered_packets)
            for filtered_packet in self.filtered_packets :
                self.pyshark_packet_handler(filtered_packet)
            self.sniff_packets(filter=filter)
        else :
            try : 
                self.stop()
            except Exception :
                pass
            self.sniff_packets()

    def stop(self):
        self.stop_sniffing.set()  # Signal the thread to stop
        if self.pyshark_sniffer:
            # Ensure the capture is closed properly
            try:
                self.pyshark_sniffer.close()
            except Exception as e:
                print(f"Error closing capture: {e}")
            self.pyshark_sniffer = None  # Clear the reference
        if self.sniff_instance.is_alive():
            self.sniff_instance.join(timeout=2)  # Wait for thread to finish


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


class ReconTab(QWidget):
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self.initUI()

    def initUI(self):
        # Create widgets for each scan page
        self.pages = {
            'ARP Scan': self.create_scan_page('ARP Scan'),
            'TCP SYN Scan': self.create_scan_page('TCP SYN Scan'),
            'TCP ACK Scan': self.create_scan_page('TCP ACK Scan'),
            'UDP Ping': self.create_scan_page('UDP Ping'),
            'ICMP Scan': self.create_scan_page('ICMP Scan'),
            'TCP Traceroute': self.create_scan_page('TCP Traceroute'),
            'Idle Scan': self.create_scan_page('Idle Scan'),
            'FIN Scan': self.create_scan_page('FIN Scan'),
            'Null Scan': self.create_scan_page('Null Scan'),
            'Xmas Scan': self.create_scan_page('Xmas Scan'),
        }
        
        # Create a stacked widget for page transitions
        self.stacked_widget = QStackedWidget()

        # Create the main menu page
        self.main_menu_page = self.create_main_menu_page()

        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.main_menu_page)
        for page_name, page_widget in self.pages.items():
            self.stacked_widget.addWidget(page_widget)

        # Create the main layout
        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

    def create_main_menu_page(self):
        page = QWidget()
        layout = QGridLayout(page)

        button_names = [
            "ARP Scan", "TCP SYN Scan", "TCP ACK Scan", "UDP Ping",
            "ICMP Scan", "TCP Traceroute",  "Idle Scan", "FIN Scan", 
            "Null Scan", "Xmas Scan"
        ]

        positions = [(i, j) for i in range(3) for j in range(4)]

        for pos, name in zip(positions, button_names):
            button = QPushButton(name)
            button.setFixedSize(150, 150)  # Larger button size
            button.setStyleSheet("""
            QPushButton {
                background-color: #4B3E4D  ;
                border-radius: 0px;
                color: white;
                font-size: 16px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #CC527A;
            }
            QPushButton:pressed {
                background-color: #CC527A;
            }
        """)
            button.clicked.connect(lambda _, n=name: self.switch_page(n))
            layout.addWidget(button, *pos)

        return page

    def create_scan_page(self, scan_name):
        """Create a page for each scan type with relevant content."""
        page = QWidget()
        page_layout = QVBoxLayout()

        # Add a back button to return to the main menu
        back_button = QPushButton("Back to Menu")
        back_button.setStyleSheet("""
            QPushButton {
                background-color: #202C31  ; }""")
        back_button.clicked.connect(self.show_main_menu)
        page_layout.addWidget(back_button)

        page.setLayout(page_layout)
        return page

    def switch_page(self, page_name):
        """Switch to the selected page."""
        if page_name in self.pages:
            index = self.stacked_widget.indexOf(self.pages[page_name])
            if index != -1:
                self.stacked_widget.setCurrentIndex(index)

    def show_main_menu(self):
        """Show the main menu page."""
        index = self.stacked_widget.indexOf(self.main_menu_page)
        if index != -1:
            self.stacked_widget.setCurrentIndex(index)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('netsec.ico'))

    sniffer_app = SnifferApp()
    sniffer_app.show()
    sys.exit(app.exec_())
