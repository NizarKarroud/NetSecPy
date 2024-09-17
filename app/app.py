import csv , os , asyncio , pyshark , socket , webbrowser , psutil , sys , io , json , inspect , subprocess
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QMenuBar,
    QAction, QStatusBar, QHBoxLayout, QFrame, QScrollArea, QRadioButton,
    QButtonGroup, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView , QLineEdit , QStackedWidget , QGridLayout , QFileDialog
    , QDialog , QTextEdit , QToolBox , QListWidget , QMessageBox , QTreeView, QFileSystemModel , QTableView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal , QAbstractTableModel
from scapy.all import  IP_PROTOS  , Ether , wrpcap , hexdump
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QThread, pyqtSignal 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from recon.scan import Scanner
from services.dhcp import DHCP
from services.dns import DNS
from monitoring.logger import Logger
from visualization.main import NTA , EtherAnalyzer , IpAnalyzer , TransportAnalyzer
from craft.craft import PacketCrafterApp


class PacketTableModel(QAbstractTableModel):
    def __init__(self):
        super(PacketTableModel, self).__init__()
        self._data = []
        self.headers = ["No.", "Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port"]
        self._packets = []  
        
    def data(self, index, role):
        if role == Qt.DisplayRole:
            if index.column() == 0:
                return str(index.row() + 1)
            else:
                return str(self._data[index.row()][index.column() - 1])  
    def rowCount(self, index):
        return len(self._data)

    def columnCount(self, index):
        return len(self.headers)

    def get_row_data(self, row):
        try :
            return self._data[row]
        except Exception :
            return None
        
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return self.headers[section]

    def addData(self, new_data, packet):
        self.beginInsertRows(self.index(self.rowCount(self), 0), self.rowCount(self), self.rowCount(self) + len(new_data) - 1)
        self._data.extend(new_data)
        self._packets.extend(packet)  
        self.endInsertRows()

    def getPacket(self, row):
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None
    
    def clearData(self):
        self.beginResetModel()  
        self._data.clear()
        self.endResetModel() 

class SnifferThread(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self, interface, filter=None):
        super().__init__()
        self.interface = interface
        self.filter = filter
        self.stop_sniffing = False
    
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        if self.filter:
            self.sniffer = pyshark.LiveCapture(interface=self.interface, display_filter=self.filter, use_json=True, include_raw=True)
        else:
            self.sniffer = pyshark.LiveCapture(interface=self.interface, use_json=True, include_raw=True)

        try:
            for packet in self.sniffer.sniff_continuously():
                if self.stop_sniffing:
                    break
                self.packet_received.emit(packet)
        except Exception as e:
            pass
        finally:
            loop.close()

    def stop(self):
        self.stop_sniffing = True
        if self.sniffer:
            self.sniffer.close()
        self.wait()

class PacketDetailsWindow(QDialog):
    def __init__(self, packet, parent=None):
        super(PacketDetailsWindow, self).__init__(parent)

        self.setWindowTitle("Packet Details")
        self.setGeometry(100, 100, 1024, 768)

        layout = QVBoxLayout()

        self.packet_text = QTextEdit(self)
        self.packet_text.setReadOnly(True)

        formatted_packet = self.format_packet(packet) + "\n Hex Dump : \n \n " + hexdump(Ether(bytes(packet.get_raw_packet())), dump=True)

        self.packet_text.setPlainText(formatted_packet)

        layout.addWidget(self.packet_text)
        self.setLayout(layout)

    def format_packet(self, pyshark_packet):
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

        self.service = service
        self.script_name = script_name


        self.setWindowTitle(f"Script: {script_name}")
        self.setGeometry(100, 100, 800, 600)


        layout = QVBoxLayout(self)


        script_label = QLabel(f"Selected Script: {script_name}")
        layout.addWidget(script_label)


        if script_name in service.scripts:

            command = service.scripts[script_name]["command"]


            command_str = ' '.join(command)
            command_label = QLabel(f"Command: {command_str}")
            layout.addWidget(command_label)


            if service.scripts[script_name].get("argument", False):
                self.arg_input = QLineEdit()  
                layout.addWidget(QLabel("Target:"))  
                layout.addWidget(self.arg_input)  


        self.result_text_area = QTextEdit()
        self.result_text_area.setReadOnly(True)  
        layout.addWidget(self.result_text_area)


        execute_button = QPushButton("Execute")
        execute_button.clicked.connect(self.execute_script)
        layout.addWidget(execute_button)


        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

    def execute_script(self):
        try:
            if hasattr(self, 'arg_input'): 
                result = self.service.run(self.script_name , self.arg_input.text()) 
            else :
                result =  self.service.run(self.script_name) 
            self.result_text_area.append(result)
        except Exception as e:
            self.result_text_area.append(f"Error executing command: {str(e)}")

class ResultWindow(QDialog):
    def __init__(self, response, parent=None):
        super(ResultWindow, self).__init__(parent)


        self.setWindowTitle("Scan Results")
        self.setGeometry(100, 100, 1024, 768)


        layout = QVBoxLayout()


        text_edit = QTextEdit()
        text_edit.setReadOnly(True)  
        text_edit.setText(response)  
        layout.addWidget(text_edit)

        self.setLayout(layout)

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.sniffer_thread = None

        self.selected_interface = None


        self.setWindowTitle("NetSecPy")
        self.setGeometry(100, 100, 1024, 768)
        self.setStyleSheet("background-color: #2A363B; color: #FFFFFF; font-family: Arial, sans-serif;")


        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)


        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)
        self.menu_bar.setStyleSheet("background-color: #2A363B; color: #FFFFFF; padding: 5px;border-bottom: 1px solid #000000;")




        documentation_menu = self.menu_bar.addMenu("Documentation")
        documentation_menu.setStyleSheet("padding: 5px;")
        docs_action = QAction("Open Documentation", self)
        docs_action.triggered.connect(self.open_documentation)
        documentation_menu.addAction(docs_action)


        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("background-color: #2A363B; color: #FFFFFF; padding: 5px;")


        self.setup_header()


        self.setup_interface_list()

    def setup_header(self):

        header_layout = QHBoxLayout()


        self.header_label = QLabel("Select Network Interface", self)
        self.header_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        self.header_label.setAlignment(Qt.AlignLeft)


        self.next_button = QPushButton("Next →", self)
        self.next_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #E84A5F; color: #FFFFFF;")
        self.next_button.clicked.connect(self.go_to_next_page)
        self.next_button.setFixedSize(100, 40)


        header_layout.addWidget(self.header_label)
        header_layout.addWidget(self.next_button, alignment=Qt.AlignRight)


        self.main_layout.addLayout(header_layout)
    
    def setup_interface_list(self):

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


        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_area.setWidget(scroll_content)


        self.main_layout.addWidget(scroll_area)


        self.interface_group = QButtonGroup()

        interfaces = psutil.net_if_addrs().items()


        self.interface_data = {}

        for interface_name, interface_addresses in interfaces:
            interface_frame = QFrame()
            interface_frame.setStyleSheet("background-color: #202C31; border-radius: 10px; margin: 10px; padding: 10px;")
            interface_layout = QHBoxLayout(interface_frame)


            radio_button = QRadioButton(interface_name, self)
            radio_button.setStyleSheet("font-size: 18px; color: #FFFFFF;")
            self.interface_group.addButton(radio_button)
            interface_layout.addWidget(radio_button)


            ip_address = None
            mac_address = None


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


            self.interface_data[interface_name] = {
                'ip': ip_address,
                'mac': mac_address,
                'netmask' : address.netmask
            }


            scroll_layout.addWidget(interface_frame)


        self.status_bar.showMessage("Monitoring network interfaces.")

    def go_to_next_page(self):

        selected_button = self.interface_group.checkedButton()
        if selected_button:
            self.selected_interface = selected_button.text()

            self.selected_ip = self.interface_data[self.selected_interface]['ip']
            self.selected_mac = self.interface_data[self.selected_interface]['mac']
            self.selected_subent = self.interface_data[self.selected_interface]['netmask']
            
            self.scanner = Scanner(self.selected_mac.replace("-",":"), self.selected_ip ,self.selected_subent ) 

            self.show_next_page()
        else:
            self.status_bar.showMessage("Please select an interface before proceeding.")

    def show_next_page(self):

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
        

        if self.central_widget is not None:
            self.central_widget.setParent(None)


        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)


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


        self.packet_sniffer = SnifferTab(self.selected_interface)
        self.logger = Logger()
        self.tabs.addTab(self.packet_sniffer, "Packet Sniffer")

        self.recon_tab = ReconTab(scanner=self.scanner)
        self.tabs.addTab(self.recon_tab, "Recon")
        
        self.add_services_tab()

        self.analyzer_tab = AnalysisTab(self ) 
        self.tabs.addTab(self.analyzer_tab, "Analysis")

        self.add_packet_crafter_tab("Packet Crafter ", "#2A363B")
        
        self.log_tab = LoggerTab(Logger.base_dir)
        self.tabs.addTab(self.log_tab, "Logs")

    def open_script_window(self, item, service):

        script_window = ScriptWindow(service, item.text(), self)
        script_window.exec_()

    def add_service(self, title, service):
        service_widget = QWidget()
        service_layout = QVBoxLayout(service_widget)
        script_list = QListWidget()
        script_list.addItems([script for script in service.scripts.keys()])
        service_layout.addWidget(script_list)
        

        script_list.itemClicked.connect(lambda item: self.open_script_window(item, service))

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

        dhcp_scanner = DHCP()
        dns_scanner = DNS()

        dhcp_service_tabs = self.add_service('DHCP' , dhcp_scanner)
        dns_service_tabs= self.add_service('DNS' , dns_scanner)

        services_layout.addWidget(self.services_toolbox)

        self.tabs.addTab(services_widget, "Services")
    
    def add_packet_crafter_tab(self, title, color):
        tab = QWidget()
        tab.setStyleSheet(f"background-color: {color};")

        main_layout = QVBoxLayout()
        tab.setLayout(main_layout)

        center_layout = QHBoxLayout()

        button = QPushButton("Initialize Packet Crafter")
        button.setStyleSheet("""
            QPushButton {
                border: 2px solid #202C31;
                border-radius: 15px;
                padding: 15px;
                background-color: #202C31;
                color: #FFFFFF;
                font-size: 20px;;
            }
            QPushButton:hover {
                background-color: #151D20;
            }
            QPushButton:pressed {
                background-color: #151D20;
            }
        """)
                             
        button.setFixedSize(300, 100)  
        button.clicked.connect(self.initialize_packet_crafter)

        center_layout.addWidget(button)
        center_layout.setAlignment(button, Qt.AlignCenter)  

        main_layout.addLayout(center_layout)
        self.tabs.addTab(tab, title)

    def initialize_packet_crafter(self):
        self.packet_crafter_window = PacketCrafterApp()
        self.packet_crafter_window.show()

    def export_as_pcap(self ):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        
        if not file_name:
            return   
        
        try :
            scapy_packets = [self.packet_sniffer.pyshark_to_scapy(packet) for packet in  self.packet_sniffer.packets]
            wrpcap(file_name,scapy_packets)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export packets: {e}")

    def export_as_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv)")
        if file_name:
            with open(file_name, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port"])
                model = self.packet_sniffer.table_model
                for row in range(model.rowCount(model)):
                    writer.writerow(model.get_row_data(row))


    def export_as_json(self):

        file_name, _ = QFileDialog.getSaveFileName(self, "Save JSON File", "", "JSON Files (*.json)")
        
        if file_name:
            data = []
            model = self.packet_sniffer.table_model

            for row in range(model.rowCount(model)):
                row_data = model.get_row_data(row)
                if row_data:
                    row_dict = {
                        "Timestamp": row_data[0],
                        "Source IP": row_data[1],
                        "Destination IP": row_data[2],
                        "Protocol": row_data[3],
                        "Length": row_data[4],
                        "Source Port": row_data[5],
                        "Destination Port": row_data[6]
                    }
                    data.append(row_dict)

            with open(file_name, 'w', newline='') as file:
                json.dump(data, file, indent=4)
                
    def open_documentation(self):
        webbrowser.open("https://github.com/NizarKarroud/NetSecPy")

    
    def closeEvent(self, event):
        if hasattr(self , "packet_sniffer") and self.packet_sniffer.sniffer_thread and self.packet_sniffer.sniffer_thread.isRunning():
            self.packet_sniffer.sniffer_thread.stop()
        
        if hasattr(self, 'logger') and self.logger and len(self.packet_sniffer.packets)>0:
            self.logger.save_pcap([self.packet_sniffer.pyshark_to_scapy(packet) for packet in self.packet_sniffer.packets])

        if os.path.exists("temp.pcap"):
            os.remove("temp.pcap")
    
        event.accept()

class SnifferTab(QWidget):
    def __init__(self,selected_interface):
        super().__init__()
        self.paused = False
        self.packets = []
        self.selected_interface = selected_interface
        self.table_model = PacketTableModel()
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.clicked.connect(self.on_row_click)

        self.table_view.horizontalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #99B898;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #444444;
            }
        """)
        self.table_view.verticalHeader().setStyleSheet("""
            QHeaderView::section {
                background-color: #99B898;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #444444;
            }
        """)
        self.table_view.setStyleSheet("""
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

            QScrollBar:horizontal {
                border: 1px solid #555555;
                background: #2A363B;
                height: 12px;
            }
            QScrollBar::handle:horizontal {
                background: #777777;
                border-radius: 6px;
            }
            QScrollBar::add-line:horizontal {
                border: 1px solid #555555;
                background: #2A363B;
                width: 0px;
            }
            QScrollBar::sub-line:horizontal {
                border: 1px solid #555555;
                background: #2A363B;
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: #2A363B;
            }
        """)

        filter_layout = QHBoxLayout()

        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter Display filter...")
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
                background-color: #151D20;
            }
            QPushButton:pressed {
                background-color: #151D20;
            }
        """)
        filter_layout.addWidget(self.apply_filter_button)

        self.apply_filter_button.clicked.connect(self.apply_filters)

        layout = QVBoxLayout()
        layout.addLayout(filter_layout)  
        layout.addWidget(self.table_view)

        self.pause_button = QPushButton("Pause", self)
        self.pause_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #202C31; color: #FFFFFF;")
        self.pause_button.clicked.connect(self.toggle_pause)
        layout.addWidget(self.pause_button)

        self.setLayout(layout)

        self.start_sniffing()


    def start_sniffing(self):
        if hasattr(self , "sniffer_thread" ) and self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        filter = self.filter_input.text()
        self.sniffer_thread = SnifferThread(self.selected_interface, filter)
        self.sniffer_thread.packet_received.connect(self.process_packet)
        self.sniffer_thread.start()


    def toggle_pause(self):
        if self.paused:
            self.paused = False
            self.start_sniffing()
            self.pause_button.setText("Pause")
        else:
            self.paused = True
            self.sniffer_thread.stop()
            self.pause_button.setText("Resume")

    def process_packet(self, packet , filtered_from_pcap=False):
        self.packets.append(packet)
        try:
            timestamp = str(packet.sniff_time)
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                proto = IP_PROTOS.d.get(int(packet.ip.proto), f"{packet.ip.proto}")
            else :
                src_ip = "N/A"
                dst_ip = "N/A"
                proto = "N/A"

            length = str(len(packet))

            try:
                if hasattr(packet, proto):
                    layer = getattr(packet, proto)
                    src_port = str(getattr(layer, 'srcport', "N/A")) 
                    dst_port = str(getattr(layer, 'dstport', "N/A"))
                else:
                    src_port = "N/A"
                    dst_port = "N/A"
            except Exception:
                src_port = "N/A"
                dst_port = "N/A"

            row_data = [str(timestamp), src_ip, dst_ip, proto, length, src_port, dst_port]

            self.table_model.addData([row_data], [packet])  

        except Exception as e:
            print(f"Error processing packet: {e}")

    def on_row_click(self, index):
        row = index.row()
        packet = self.table_model.getPacket(row) 
        if packet:
            details_window = PacketDetailsWindow(packet)
            details_window.exec_()


    def apply_filters(self):
        self.sniffer_thread.stop()
        self.sniffer_thread.wait()
        self.table_model.clearData()
        if self.filter_input.text() :
            wrpcap("temp.pcap" , [self.pyshark_to_scapy(packet) for packet in  self.table_model._packets])
            self.filtered_packets = [packet for packet in pyshark.FileCapture('temp.pcap', display_filter=self.filter_input.text() , use_json=True , include_raw=True) ]
            self.table_model._packets.clear()  
            for filtered_packet in self.filtered_packets :
                self.process_packet(filtered_packet , filtered_from_pcap=True)
        self.start_sniffing()

    def pyshark_to_scapy(self , pyshark_packet):
        raw_bytes = bytes(pyshark_packet.get_raw_packet())

        scapy_packet = Ether(raw_bytes)
        return scapy_packet

class LoggerTab(QWidget):
    def __init__(self, logs_dir):
        super().__init__()
        self.logs_dir = logs_dir
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()

        logs_dir_label = QLabel(f"{self.logs_dir}")
        logs_dir_label.setAlignment(Qt.AlignCenter)
        logs_dir_label.setStyleSheet("font-weight: bold;")  

        layout.addWidget(logs_dir_label)


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


        self.model = QFileSystemModel()
        self.model.setRootPath(self.logs_dir)

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
            'OS Detection' :self.scanner.os
        }


        for scan_name, scan_function in scan_types.items():
            page = ScanPage(scan_name, self.show_main_menu, scan_function)
            self.pages[scan_name] = page
            self.stacked_widget.addWidget(page)


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
            "Null Scan", "Xmas Scan" , "OS Detection"
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


        self.create_input_fields()


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


        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.page_layout.addWidget(self.result_area)
       

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


            label = QLabel(f"{param_name.capitalize()}:")
            self.page_layout.addWidget(label)


            line_edit = QLineEdit()


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


            param = function_signature.parameters.get(param_name)
            if param:
                param_type = param.annotation


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

class AnalysisTab(QWidget):
    def __init__(self, parent=None):
        super(AnalysisTab, self).__init__(parent)
        self.init_ui()
        self.parent = parent

    def init_ui(self):

            self.stacked_widget = QStackedWidget(self)
            

            self.choice_page = QWidget()
            self.choice_layout = QVBoxLayout(self.choice_page)
            

            self.packet_radio = QRadioButton("Packets")
            self.file_radio = QRadioButton("File")
            self.file_radio.setChecked(True)  
                    

            self.next_button = QPushButton("Next")
            self.next_button.setStyleSheet("""
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
            self.next_button.clicked.connect(self.next_page)
            

            self.choice_layout.addWidget(self.packet_radio)
            self.choice_layout.addWidget(self.file_radio)
            self.choice_layout.addWidget(self.next_button)
            
            self.stacked_widget.addWidget(self.choice_page)
            

            self.analysis_page = QWidget()
            self.analysis_layout = QVBoxLayout(self.analysis_page)
            self.update_packets_button = QPushButton("Update Packets")
            self.update_packets_button.setVisible(False)  
            self.update_packets_button.clicked.connect(self.update_packets)

            self.analysis_layout.addWidget(self.update_packets_button)


            self.toolbox = QToolBox()
            self.toolbox.setStyleSheet("""
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
            

            self.add_analysis_section("Ethernet Layer", [
                "Communication Graph", "MAC Frequency Analysis", "Mac Pairs Analysis", 
                "Analyze Ethernet Types", "Detect ARP scanning", "Broadcast Traffic Analysis"
            ])
            self.add_analysis_section("IP Layer", [
                "IP Communication Graph", "Analyze TTL", "IP Frequency Analysis", 
                "IP Pair Analysis", "High Traffic IPs"
            ])
            self.add_analysis_section("Transport Layer", [
                "Detect UDP port Scanning", "Analyze UDP len", "UDP Port Distribution", 
                "TCP Flags Distribution", "TCP Port Distribution" , "Unusual TCP Port Activity" , "IP / Port distribution"
            ])
            
            self.analysis_layout.addWidget(self.toolbox)
            self.stacked_widget.addWidget(self.analysis_page)
            

            main_layout = QVBoxLayout(self)
            main_layout.addWidget(self.stacked_widget)
            self.setLayout(main_layout)
            

            self.selected_file_path = None
            

            self.stacked_widget.setCurrentWidget(self.choice_page)


    def update_packets(self):
        """
        Reinitialize the NTA, EtherAnalyzer, and IpAnalyzer with the updated packet data for a "Live analysis".
        """
        if hasattr(self, 'nta'):
            del self.nta
        if hasattr(self, 'ether_analyser'):
            del self.ether_analyser
        if hasattr(self, 'ip_analyser'):
            del self.ip_analyser
        self.nta = NTA(packets=[self.parent.packet_sniffer.pyshark_to_scapy(packet) for packet in self.parent.packet_sniffer.packets])
        self.ether_analyser = EtherAnalyzer(self.nta.data)
        self.ip_analyser = IpAnalyzer(self.nta.data)
        self.transport_analyser = TransportAnalyzer(self.nta.data)
        self.analysis_methods = {
            "Communication Graph": self.ether_analyser.visualize_ether_communication_graph,
            "MAC Frequency Analysis": self.ether_analyser.mac_frequency_analysis,
            "Mac Pairs Analysis": self.ether_analyser.mac_pair_analysis,
            "Analyze Ethernet Types": self.ether_analyser.analyze_traffic_types,
            "Detect ARP scanning": self.ether_analyser.detect_arp_scanning,
            "Broadcast Traffic Analysis": self.ether_analyser.broadcast_traffic_analysis,
            "IP Communication Graph": self.ip_analyser.visualize_ip_communication_graph,
            "Analyze TTL": self.ip_analyser.analyze_ttl,
            "IP Frequency Analysis": self.ip_analyser.ip_frequency_analysis,
            "IP Pair Analysis": self.ip_analyser.ip_pair_analysis,
            "High Traffic IPs": self.ip_analyser.monitor_high_traffic_ips,
            "Detect UDP port Scanning" :self.transport_analyser.detect_udp_port_scanning ,
            "Analyze UDP len" :self.transport_analyser.analyze_udp_lengths ,
            "UDP Port Distribution" :self.transport_analyser.udp_port_distribution , 
            "TCP Flags Distribution" : self.transport_analyser.tcp_flags_distribution, 
            "TCP Port Distribution" : self.transport_analyser.tcp_port_distribution , 
            "Unusual TCP Port Activity"  : self.transport_analyser.detect_unusual_port_activity , 
            "IP / Port distribution" : self.transport_analyser.analyze_ip_most_used_ports
        }
    
        QMessageBox.information(self, "Update", "Packets updated successfully.")

    def add_analysis_section(self, title, items):

        section_widget = QWidget()
        section_layout = QVBoxLayout(section_widget)
        
        list_widget = QListWidget()
        list_widget.addItems(items)
        section_layout.addWidget(list_widget)
        
        self.toolbox.addItem(section_widget, title)
        
        list_widget.itemClicked.connect(self.handle_analysis_selection)
        
    def open_file_dialog(self):
        if self.file_radio.isChecked():
            options = QFileDialog.Options()
            options |= QFileDialog.ReadOnly
            file_path, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "All Files (*);;Pcap Files (*.pcap)", options=options)
            
            if file_path:
                self.selected_file_path = file_path
                self.nta = NTA(pcap_file=self.selected_file_path)

                self.stacked_widget.setCurrentWidget(self.analysis_page)
                
    def next_page(self):
        if self.file_radio.isChecked():
            self.open_file_dialog()
        else:
            self.update_packets_button.setVisible(True)  
            self.nta = NTA(packets=[self.parent.packet_sniffer.pyshark_to_scapy(packet) for packet in self.parent.packet_sniffer.packets])
            self.stacked_widget.setCurrentWidget(self.analysis_page)
   
        self.ether_analyser = EtherAnalyzer(self.nta.data)
        self.ip_analyser = IpAnalyzer(self.nta.data)
        self.transport_analyser = TransportAnalyzer(self.nta.data)
        
        self.analysis_methods = {
            "Communication Graph": self.ether_analyser.visualize_ether_communication_graph,
            "MAC Frequency Analysis": self.ether_analyser.mac_frequency_analysis,
            "Mac Pairs Analysis": self.ether_analyser.mac_pair_analysis,
            "Analyze Ethernet Types": self.ether_analyser.analyze_traffic_types,
            "Detect ARP scanning": self.ether_analyser.detect_arp_scanning,
            "Broadcast Traffic Analysis": self.ether_analyser.broadcast_traffic_analysis,
            "IP Communication Graph": self.ip_analyser.visualize_ip_communication_graph,
            "Analyze TTL": self.ip_analyser.analyze_ttl,
            "IP Frequency Analysis": self.ip_analyser.ip_frequency_analysis,
            "IP Pair Analysis": self.ip_analyser.ip_pair_analysis,
            "High Traffic IPs": self.ip_analyser.monitor_high_traffic_ips ,
            "Detect UDP port Scanning" :self.transport_analyser.detect_udp_port_scanning ,
            "Analyze UDP len" :self.transport_analyser.analyze_udp_lengths ,
            "UDP Port Distribution" :self.transport_analyser.udp_port_distribution , 
            "TCP Flags Distribution" : self.transport_analyser.tcp_flags_distribution, 
            "TCP Port Distribution" : self.transport_analyser.tcp_port_distribution , 
            "Unusual TCP Port Activity"  : self.transport_analyser.detect_unusual_port_activity , 
            "IP / Port distribution" : self.transport_analyser.analyze_ip_most_used_ports

        }
    
    def handle_analysis_selection(self, item):
        selected_analysis = item.text()
        try:
            method = self.analysis_methods.get(selected_analysis)
            if method:
                result = method() 
                if isinstance(result, pd.DataFrame):

                    self.prompt_save_dataframe(result)
                    
                elif isinstance(result, tuple) and all(isinstance(df, pd.DataFrame) for df in result):

                    for i, df in enumerate(result):
                        self.prompt_save_dataframe(df, index=i + 1)
          
            else:
                raise ValueError(f"Unknown analysis type: {selected_analysis}")
        
        except AttributeError as e:
            QMessageBox.warning(self, "Error", f"Method not implemented: {e}")


    def prompt_save_dataframe(self, dataframe, index=None):

        reply = QMessageBox.question(self, 'Save Data', 'Do you want to save the dataframe as a CSV file?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:

            options = QFileDialog.Options()
            default_name = f"dataframe_{index}.csv" if index else "dataframe.csv"
            file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV File", default_name, "CSV Files (*.csv);;All Files (*)", options=options)
            
            if file_path:
                dataframe.to_csv(file_path, index=False) 

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('netsec.ico'))

    sniffer_app = SnifferApp()
    sniffer_app.show()
    sys.exit(app.exec_())

