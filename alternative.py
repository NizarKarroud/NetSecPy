from PyQt5.QtCore import QAbstractTableModel, Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QTableView, QVBoxLayout, QWidget, QApplication , QDialog, QTextEdit, QTabWidget , QMainWindow , QAction , QHBoxLayout ,QLineEdit ,QPushButton
import pyshark
import asyncio
from scapy.all import Ether, hexdump , IP_PROTOS
import io

class PacketTableModel(QAbstractTableModel):
    def __init__(self, data):
        super(PacketTableModel, self).__init__()
        self._data = data
        self.headers = ["No.", "Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port"]
        self._packets = []  # Store packets directly here

    def data(self, index, role):
        if role == Qt.DisplayRole:
            if index.column() == 0:
                # Display row number
                return str(index.row() + 1)
            else:
                return str(self._data[index.row()][index.column() - 1])  # Adjust column index for data

    def rowCount(self, index):
        return len(self._data)

    def columnCount(self, index):
        return len(self.headers)

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return self.headers[section]

    def addData(self, new_data, packet):
        self.beginInsertRows(self.index(self.rowCount(self), 0), self.rowCount(self), self.rowCount(self) + len(new_data) - 1)
        self._data.extend(new_data)
        self._packets.extend(packet)  # Store the actual packets
        self.endInsertRows()

    def getPacket(self, row):
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None

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

class PacketSnifferUI(QWidget):
    def __init__(self,selected_interface="Wi-Fi"):
        super().__init__()
        self.paused = False

        self.selected_interface = selected_interface
        self.packet_data = []
        self.table_model = PacketTableModel(self.packet_data)
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

        # Filter input and apply button layout
        filter_layout = QHBoxLayout()

        # Add the filter input and button
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

        # Connect button to filter logic (placeholder for now)
        self.apply_filter_button.clicked.connect(self.apply_filters)

        # Set layout
        layout = QVBoxLayout()
        layout.addLayout(filter_layout)  # Add the filter layout first
        layout.addWidget(self.table_view)

        self.pause_button = QPushButton("Pause", self)
        self.pause_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #202C31; color: #FFFFFF;")
        self.pause_button.clicked.connect(self.toggle_pause)
        layout.addWidget(self.pause_button)

        self.setLayout(layout)

        self.start_sniffing()

    def apply_filters(self):
        print(len(self.packet_data))

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

    def process_packet(self, packet):
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
            self.table_model.addData([row_data], [packet])  # Store the actual packet with the data


        except Exception as e:
            print(f"Error processing packet: {e}")

    def on_row_click(self, index):
        row = index.row()
        packet = self.table_model.getPacket(row)  # Retrieve the actual packet from the model
        if packet:
            details_window = PacketDetailsWindow(packet)
            details_window.exec_()

    def closeEvent(self, event):
        # Stop the sniffer thread on window close
        self.sniffer_thread.stop()
        event.accept()



class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Main Application')
        self.setGeometry(100, 100, 1200, 800)

        # Create a central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Create a tab widget
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)

        # Create and add the PacketSnifferUI widget
        self.packet_sniffer_ui = PacketSnifferUI()
        self.tab_widget.addTab(self.packet_sniffer_ui, "Packet Sniffer")

        # Optional: Add a menu bar with a simple 'File' menu
        self.menu_bar = self.menuBar()
        file_menu = self.menu_bar.addMenu('File')
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    main_app = MainApp()
    main_app.show()
    sys.exit(app.exec_())