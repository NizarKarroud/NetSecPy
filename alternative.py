from PyQt5.QtCore import QAbstractTableModel, Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QTableView, QVBoxLayout, QWidget, QApplication , QDialog, QTextEdit
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

    def addData(self, new_data, packets):
        self.beginInsertRows(self.index(self.rowCount(self), 0), self.rowCount(self), self.rowCount(self) + len(new_data) - 1)
        self._data.extend(new_data)
        self._packets.extend(packets)  # Store the actual packets
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
    def __init__(self):
        super().__init__()

        # Initialize the packet table model and view
        self.packet_data = []
        self.packet_map = []  # To store packets by index
        self.table_model = PacketTableModel(self.packet_data)
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.clicked.connect(self.on_row_click)

        # Set layout
        layout = QVBoxLayout()
        layout.addWidget(self.table_view)
        self.setLayout(layout)

        # Start the sniffer thread
        self.sniffer_thread = SnifferThread(interface='Wi-Fi') 
        self.sniffer_thread.packet_received.connect(self.process_packet)
        self.sniffer_thread.start()

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

            # Update the table model
            self.table_model.addData([row_data])
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

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = PacketSnifferUI()
    window.show()
    sys.exit(app.exec_())
