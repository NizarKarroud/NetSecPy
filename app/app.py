import csv , os , asyncio , pyshark , socket , webbrowser , psutil , sys , io , json , inspect , subprocess
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QMenuBar,
    QAction, QStatusBar, QHBoxLayout, QFrame, QScrollArea, QRadioButton,
    QButtonGroup, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView , QLineEdit , QStackedWidget , QGridLayout , QFileDialog
    , QDialog , QTextEdit , QToolBox , QListWidget , QFormLayout , QMessageBox , QTreeView, QFileSystemModel
)
from PyQt5.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot ,  QThread, pyqtSignal
from scapy.all import  IP_PROTOS  , Ether , wrpcap
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QThread, pyqtSignal 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from recon.scan import Scanner
from services.dhcp import DHCP
from services.dns import DNS
from services.ssh import SSH
from services.snmp import SNMP
from visualization.test import packet_to_data 
from monitoring.logger import Logger

class SnifferThread(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self, interface, filter=None):
        super().__init__()
        self.interface = interface
        self.filter = filter
        self.stop_sniffing = False
    
    def run(self):
        # Create and set up an asyncio event loop in this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        if self.filter:
            self.sniffer = pyshark.LiveCapture(interface=self.interface, display_filter=self.filter , use_json =True ,  include_raw = True )
        else:
            self.sniffer = pyshark.LiveCapture(interface=self.interface, use_json =True ,  include_raw = True )
        
        try:
            for packet in self.sniffer.sniff_continuously():
                if self.stop_sniffing:
                    break
                self.packet_received.emit(packet)
        except Exception as e:
            pass
        finally:
            loop.close()  # Close the event loop when done

    def stop(self):
        self.stop_sniffing = True
        if self.sniffer:
            self.sniffer.close()
        self.wait()  # Ensure the thread has finished

class PacketDetailsWindow(QDialog):
    def __init__(self, packet, parent=None):
        super(PacketDetailsWindow, self).__init__(parent)

        self.setWindowTitle("Packet Details")
        self.setGeometry(100, 100, 1024, 768)

        # Create a layout
        layout = QVBoxLayout()

        # Create a QTextEdit widget to display packet details
        self.packet_text = QTextEdit(self)
        self.packet_text.setReadOnly(True)

        formatted_packet = self.format_packet(packet)
        
        # Add the formatted packet details to the QTextEdit
        self.packet_text.setPlainText(formatted_packet)

        # Add the QTextEdit to the layout
        layout.addWidget(self.packet_text)

        # Set the layout for the dialog
        self.setLayout(layout)

    def format_packet(self , pyshark_packet):
        raw_bytes = bytes(pyshark_packet.get_raw_packet())
        packet = Ether(raw_bytes)

        output_buffer = io.StringIO()

        sys.stdout = output_buffer

        packet.show()

        sys.stdout = sys.__stdout__

        captured_output = output_buffer.getvalue()

        output_buffer.close()

        return captured_output
    
class ScriptWindow(QDialog):
    def __init__(self, service, script_name, parent=None):
        super(ScriptWindow, self).__init__(parent)

        # Set the title and geometry of the window
        self.setWindowTitle(f"Script: {script_name}")
        self.setGeometry(100, 100, 800, 600)

        # Create a layout for the window
        layout = QVBoxLayout(self)

        # Add a label to display the selected script name
        script_label = QLabel(f"Selected Script: {script_name}")
        layout.addWidget(script_label)

        # Add a section for the command and its arguments
        if script_name in service.scripts:
            command = service.scripts[script_name]
            
            # Safely get arguments if they exist, or default to an empty list
            args = getattr(service, 'script_args', {}).get(script_name, [])

            # Create a widget for the command and its arguments
            command_widget = QWidget()
            command_layout = QFormLayout(command_widget)
            
            # Add the command label
            command_label = QLabel(f"Command: {command}")
            command_layout.addRow(command_label)

            # Add text inputs for each argument
            self.arg_inputs = {}  # Dictionary to store argument input widgets
            for arg in args:
                arg_label = QLabel(arg)
                arg_input = QLineEdit()
                command_layout.addRow(arg_label, arg_input)
                self.arg_inputs[arg] = arg_input  # Store the input widget with its label

            # Add the command widget to the main layout
            layout.addWidget(command_widget)

        # Close button to close the dialog
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

    def get_input_values(self):
        """Retrieve the values entered in the text inputs."""
        return {arg: input_widget.text() for arg, input_widget in self.arg_inputs.items()}

class ResultWindow(QDialog):
    def __init__(self, response, parent=None):
        super(ResultWindow, self).__init__(parent)

        # Set the title and geometry of the window
        self.setWindowTitle("Scan Results")
        self.setGeometry(100, 100, 1024, 768)

        # Create a layout for the dialog
        layout = QVBoxLayout()

        # Add a QTextEdit to display the response
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)  # Make it read-only
        text_edit.setText(response)  # Display the response
        layout.addWidget(text_edit)

        self.setLayout(layout)

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.sniffer_thread = None

        self.packets = []
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
        # File Menu
        file_menu = self.menu_bar.addMenu("File")
        file_menu.setStyleSheet("padding: 5px;")
        open_action = QAction("Export as pcap", self)
        open_action.triggered.connect(self.export_as_pcap)
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
        
        self.log_tab = LoggerTab(Logger.base_dir)
        self.tabs.addTab(self.log_tab, "Logs")

        self.add_services_tab()  
        self.add_tab("Visualization", "#2A363B")
        self.add_tab("Packet Crafter ", "#2A363B")


    def open_script_window(self, item):
    # Create an instance of the ScriptWindow class
        script_window = ScriptWindow(self.current_service ,item.text() , self)

        script_window.exec_()
    
    def add_service(self, title , service):
        service_widget = QWidget()
        service_layout = QVBoxLayout(service_widget)
        self.current_service = service
        script_list = QListWidget()
        script_list.addItems([script for script in service.scripts.keys()])
        service_layout.addWidget(script_list)
        
        # Connect the script selection to open a new window
        script_list.itemClicked.connect(self.open_script_window)

        self.services_toolbox.addItem(service_widget, title)
        return service_widget

    def add_services_tab(self):
        services_widget = QWidget()
        services_layout = QVBoxLayout(services_widget)
        
        self.services_toolbox = QToolBox()
        self.services_toolbox.setStyleSheet("""
            QToolBox::tab {
                background: #202C31;
                color: #FFFFFF;
                border: 1px solid #444444;
                padding: 2px 16px; 
                min-height: 50px; 
                min-width: 150px; 
            }
            QToolBox::tab:selected {
                background: #202C31;
                font-weight: bold;
            }
        """)
        # Example services with a list of scripts
        dhcp_scanner = DHCP()
        dns_scanner = DNS()
        ssh_scanner = SSH()
        snmp_scanner = SNMP()

        dhcp_service_tabs = self.add_service('DHCP' , dhcp_scanner)
        dns_service_tabs= self.add_service('DNS' , dns_scanner)
        ssh_service_tab=self.add_service('SSH' , ssh_scanner)
        snmp_service_tab =self.add_service('SNMP' , snmp_scanner)

        services_layout.addWidget(self.services_toolbox)

        self.tabs.addTab(services_widget, "Services")

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

        self.apply_filter_button.clicked.connect(self.apply_filters)

        # Add the filter layout to the main layout
        layout.addLayout(filter_layout)

        # Create a QTableWidget to display captured packets
        self.sniffer_table = QTableWidget(sniffer_tab)
        self.sniffer_table.setColumnCount(7) 
        self.sniffer_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port","More Info"])

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

        self.logger = Logger()
        # Start the sniffing thread
        self.start_sniffing()

    def toggle_pause(self):
        if self.paused:
            self.paused = False
            self.start_sniffing()
            self.pause_button.setText("Pause")
        else:
            self.paused = True
            self.sniffer_thread.stop()
            self.pause_button.setText("Resume")

    def add_tab(self, title, color):
        tab = QWidget()
        tab.setStyleSheet(f"background-color: {color};")
        self.tabs.addTab(tab, title)

    def start_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        filter = self.filter_input.text()
        self.sniffer_thread = SnifferThread(self.selected_interface, filter)
        self.sniffer_thread.packet_received.connect(self.pyshark_packet_handler)
        self.sniffer_thread.start()

    def pyshark_packet_handler(self , packet , filtered_from_pcap=False):
        if filtered_from_pcap == False :
            self.packets.append(packet)
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
                Q_ARG(str, dst_port),
                Q_ARG(object, packet)  # Pass the entire packet object
            )

    def apply_filters(self):
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.sniffer_table.setRowCount(0)
            if self.filter_input.text() :
                wrpcap("temp.pcap" , [self.pyshark_to_scapy(packet) for packet in  self.packets])
                self.filtered_packets = [packet for packet in pyshark.FileCapture('temp.pcap', display_filter=self.filter_input.text() , use_json=True , include_raw=True) ]
                for filtered_packet in self.filtered_packets :
                    self.pyshark_packet_handler(filtered_packet , filtered_from_pcap=True)
            self.start_sniffing()

    @pyqtSlot(str, str, str, str , str , str , object)
    def update_table(self, src_ip, dest_ip, proto, length , src_port , dst_port , packet):
        if not self.paused:
            row_position = self.sniffer_table.rowCount()
            self.sniffer_table.insertRow(row_position)
            self.sniffer_table.setItem(row_position, 0, QTableWidgetItem(src_ip))
            self.sniffer_table.setItem(row_position, 1, QTableWidgetItem(dest_ip))
            self.sniffer_table.setItem(row_position, 2, QTableWidgetItem(proto))
            self.sniffer_table.setItem(row_position, 3, QTableWidgetItem(length))
            self.sniffer_table.setItem(row_position, 4, QTableWidgetItem(src_port))
            self.sniffer_table.setItem(row_position, 5, QTableWidgetItem(dst_port))

            more_info_button = QPushButton("More Info")
            more_info_button.setStyleSheet("""
                QPushButton {
                    background-color: #202C31;
                    color: #FFFFFF;
                    font-size: 14px;
                    padding: 5px;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #151D20;
                }
                QPushButton:pressed {
                    background-color: #0F1416;
                }
            """)
            more_info_button.clicked.connect(lambda : self.show_packet(packet))

            # Set the button in the "More Info" column
            self.sniffer_table.setCellWidget(row_position, 6, more_info_button)

    def show_packet(self,packet):
        details_window = PacketDetailsWindow(packet,self)
        details_window.exec_()  

    def export_as_pcap(self ):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        
        if not file_name:
            return  # User canceled the dialog
        
        try :
            scapy_packets = [self.pyshark_to_scapy(packet) for packet in  self.packets]
            wrpcap(file_name,scapy_packets)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export packets: {e}")

    def export_as_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv)")
        if file_name:
            with open(file_name, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port"])
                for row in range(self.sniffer_table.rowCount()):
                    row_data = [self.sniffer_table.item(row, col).text()for col in range(0,6)]
                    writer.writerow(row_data)

    def export_as_json(self):
        # Open a file dialog to choose where to save the JSON file
        file_name, _ = QFileDialog.getSaveFileName(self, "Save JSON File", "", "JSON Files (*.json)")
        
        if file_name:
            data = []
            # Iterate over each row in the table
            for row in range(self.sniffer_table.rowCount()):
                row_data = {}
                for col in range(6):
                    item = self.sniffer_table.item(row, col)
                    
                    # Check if item is valid and a QTableWidgetItem
                    if isinstance(item, QTableWidgetItem):
                        header = self.sniffer_table.horizontalHeaderItem(col).text()  # Get the column header
                        row_data[header] = item.text()
                    else:
                        header = self.sniffer_table.horizontalHeaderItem(col).text()  # Get the column header
                        row_data[header] = ""
                
                # Add the row data to the list
                data.append(row_data)
            
            # Write the data to a JSON file
            with open(file_name, 'w', newline='') as file:
                json.dump(data, file, indent=4)
                
    def open_documentation(self):
        webbrowser.open("https://your.documentation.url")

    def pyshark_to_scapy(self , pyshark_packet):
        raw_bytes = bytes(pyshark_packet.get_raw_packet())
        # Create a Scapy packet from the raw bytes
        scapy_packet = Ether(raw_bytes)
        return scapy_packet
    
    def closeEvent(self, event):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
        
        if hasattr(self, 'logger') and self.logger and len(self.packets)>0:
            self.logger.save_pcap([self.pyshark_to_scapy(packet) for packet in self.packets])

        if os.path.exists("temp.pcap"):
            os.remove("temp.pcap")
    
        # Call the base class implementation
        event.accept()

class LoggerTab(QWidget):
    def __init__(self, logs_dir):
        super().__init__()
        self.logs_dir = logs_dir
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()

        logs_dir_label = QLabel(f"{self.logs_dir}")
        logs_dir_label.setAlignment(Qt.AlignCenter)  # Center the label text
        logs_dir_label.setStyleSheet("font-weight: bold;")  # Make the text bold

        layout.addWidget(logs_dir_label)

        # Create a button that opens the file explorer at the logs directory
        open_button = QPushButton("Open in File Explorer")
        open_button.setStyleSheet("""
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
        open_button.clicked.connect(self.open_file_explorer)
        layout.addWidget(open_button)

        # Set up file system model
        self.model = QFileSystemModel()
        self.model.setRootPath(self.logs_dir)

        # Create a tree view and set its model
        self.tree = QTreeView()
        self.tree.setStyleSheet("""
            QHeaderView::section {
                background-color: #151D20;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #151D20;
            }
        """)
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(self.logs_dir))
        self.tree.setColumnWidth(0, 250)

        # Add the tree view to the layout
        layout.addWidget(self.tree)
        
        self.setLayout(layout)

    def open_file_explorer(self):
        if os.name == 'nt':  # Windows
            subprocess.Popen(f'explorer "{self.logs_dir}"')


class ReconTab(QWidget):
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self.initUI()

    def initUI(self):
        self.pages = {}
        self.stacked_widget = QStackedWidget()
        self.main_menu_page = self.create_main_menu_page()

        # Scan types and their corresponding function names
        scan_types = {
            'ARP Scan': self.scanner.arp_scan,
            'TCP SYN Scan': self.scanner.tcp_syn_scan,
            'TCP ACK Scan': self.scanner.tcp_ack_scan,
            'UDP Ping': self.scanner.udp_ping,
            'ICMP Scan': self.scanner.icmp,
            'TCP Traceroute': self.scanner.tcp_traceroute,
            'Idle Scan': self.scanner.idle_scan,
            'FIN Scan': self.scanner.fin_scan,
            'Null Scan': self.scanner.null_scan,
            'Xmas Scan': self.scanner.xmas_scan,
        }

        # Create pages for each scan type
        for scan_name, scan_function in scan_types.items():
            page = ScanPage(scan_name, self.show_main_menu, scan_function)
            self.pages[scan_name] = page
            self.stacked_widget.addWidget(page)

        # Add main menu to the stacked widget
        self.stacked_widget.addWidget(self.main_menu_page)
        
        self.stacked_widget.setCurrentWidget(self.main_menu_page)

        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

    def create_main_menu_page(self):
        page = QWidget()
        layout = QGridLayout(page)

        button_names = [
            "ARP Scan", "TCP SYN Scan", "TCP ACK Scan", "UDP Ping",
            "ICMP Scan", "TCP Traceroute", "Idle Scan", "FIN Scan", 
            "Null Scan", "Xmas Scan"
        ]

        positions = [(i, j) for i in range(3) for j in range(4)]

        for pos, name in zip(positions, button_names):
            button = QPushButton(name)
            button.setFixedSize(150, 150)
            button.setStyleSheet("""
            QPushButton {
                background-color: #4B3E4D;
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

    def switch_page(self, page_name):
        if page_name in self.pages:
            index = self.stacked_widget.indexOf(self.pages[page_name])
            if index != -1:
                self.stacked_widget.setCurrentIndex(index)

    def show_main_menu(self):
        index = self.stacked_widget.indexOf(self.main_menu_page)
        if index != -1:
            self.stacked_widget.setCurrentIndex(index)

class ScanPage(QWidget):
    def __init__(self, scan_name, main_menu_callback, scan_function, parent=None):
        super(ScanPage, self).__init__(parent)
        self.scan_name = scan_name
        self.main_menu_callback = main_menu_callback
        self.scan_function = scan_function

        self.page_layout = QVBoxLayout(self)
        self.input_fields = {}

        # Dynamically create input fields based on the scan function
        self.create_input_fields()

        # Add an Execute button
        self.execute_button = QPushButton(f"Execute {scan_name}")
        self.execute_button.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: #FFFFFF;
            }
            QPushButton:hover {
                background-color: #005f9e;
            }
        """)
        self.execute_button.clicked.connect(self.execute_scan)
        self.page_layout.addWidget(self.execute_button)

        # Text area to display results
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.page_layout.addWidget(self.result_area)
       
        # Add a back button
        self.back_button = QPushButton("Back to Menu")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #202C31;
                color: #FFFFFF;
            }
            QPushButton:hover {
                background-color: #34495E;
            }
        """)
        self.back_button.clicked.connect(self.main_menu_callback)
        self.page_layout.addWidget(self.back_button)
        
        self.setLayout(self.page_layout)


    def create_input_fields(self):
        """Dynamically create input fields based on the scan function."""
        function_signature = inspect.signature(self.scan_function)

        for param_name, param in function_signature.parameters.items():
            if param_name == 'self':
                continue

            # Create a label for the parameter
            label = QLabel(f"{param_name.capitalize()}:")
            self.page_layout.addWidget(label)

            # Create a line edit for the parameter
            line_edit = QLineEdit()

            # Set the default value if available
            if param.default is not param.empty:
                line_edit.setText(str(param.default))

            self.input_fields[param_name] = line_edit
            self.page_layout.addWidget(line_edit)

    def execute_scan(self):
        """Execute the scan function with the provided input."""
        args = []
        function_signature = inspect.signature(self.scan_function)

        for param_name, line_edit in self.input_fields.items():
            value = line_edit.text()

            # Determine the type of the parameter
            param = function_signature.parameters.get(param_name)
            if param:
                param_type = param.annotation

                # Convert value based on type hint
                if param_type is int:
                    args.append(int(value) if value else param.default)
                elif param_type is str:
                    args.append(value if value else param.default)
                else:
                    args.append(value if value else param.default)

        try:
            result = self.scan_function(*args)
            if isinstance(result, pd.DataFrame):
                self.result_area.setText(result.to_string(index=False))
            else:
                self.result_area.setText(str(result))
        except Exception as e:
            self.result_area.setText(str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('netsec.ico'))

    sniffer_app = SnifferApp()
    sniffer_app.show()
    sys.exit(app.exec_())
