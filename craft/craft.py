from scapy.all import Ether, ICMP , TCP , UDP ,IP, Raw , ETHER_TYPES , TCP_SERVICES, UDP_SERVICES  , IP_PROTOS ,sendp, send, srp, sr, sendpfast   


import sys
from PyQt5.QtWidgets import QComboBox , QTextEdit,QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QStackedWidget, QHBoxLayout, QFormLayout
from PyQt5.QtCore import Qt

class PacketCrafter:
    ether_types = ETHER_TYPES.d

    tos_dict = {
        "Network Control" : 0b111 ,
        "Internetwork Control" : 0b110,
        "CRITIC/ECP" : 0b101 ,
        "Flash Override" : 0b100,
        "Flash" : 0b011,
        "Immediate" : 0b010,
        "Priority" : 0b001,
        "Routine" :0b000
    }
    ip_protocols = IP_PROTOS.d

    icmp_types_and_codes = {
        "echo-reply": {"type": 0, "code": 0},
        "dest-unreach": {
            "type": 3,
            "codes": {
                "network-unreachable": 0,
                "host-unreachable": 1,
                "protocol-unreachable": 2,
                "port-unreachable": 3,
                "fragmentation-needed": 4,
                "source-route-failed": 5
            }
        },
        "redirect": {
            "type": 5,
            "codes": {
                "network-redirect": 0,
                "host-redirect": 1,
                "TOS-network-redirect": 2,
                "TOS-host-redirect": 3
            }
        },
        "echo-request": {"type": 8, "code": 0},
        "time-exceeded": {
            "type": 11,
            "codes": {
                "ttl-zero-during-transit": 0,
                "ttl-zero-during-reassembly": 1
            }
        },
        "parameter-problem": {
            "type": 12,
            "codes": {
                "ip-header-bad": 0,
                "required-option-missing": 1,
                "2": 2
            }
        },
        "timestamp-request": {"type": 13, "code": 0},
        "timestamp-reply": {"type": 14, "code": 0},
        "information-request": {"type": 15, "code": 0},
        "information-response": {"type": 16, "code": 0},
        "address-mask-request": {"type": 17, "code": 0},
        "address-mask-reply": {"type": 18, "code": 0}
    }
    
    tcp_services = TCP_SERVICES.d
    udp_services = UDP_SERVICES.d

    flags = {
    'FIN': 'F',
    'SYN': 'S',
    'RST': 'R',
    'PSH': 'P',
    'ACK': 'A',
    'URG': 'U',
    'ECE': 'E',
    'CWR': 'C'
    }
    
    def __init__(self) -> None:
        self.packet = None  

    
    @classmethod
    def get_ether_type_name(cls, type: int) -> str:
        """Return the name of the EtherType if known."""
        return cls.ether_types.get(type, "Unknown EtherType")
    
    @classmethod
    def get_tos_value(cls, name: str) :
        """Return the name of the EtherType if known."""
        return cls.tos_dict.get(name , 0)
    
    @classmethod
    def get_icmp_type_and_code(cls, type_name, code_name=None):
        if type_name in cls.icmp_types_and_codes:
            icmp_type = cls.icmp_types_and_codes[type_name]["type"]
            if code_name and "codes" in cls.icmp_types_and_codes[type_name]:
                icmp_code = cls.icmp_types_and_codes[type_name]["codes"].get(code_name, 0)
            else:
                icmp_code = cls.icmp_types_and_codes[type_name]["code"]
            return icmp_type, icmp_code
        else:
            raise ValueError(f"Invalid ICMP type name: {type_name}")
    
    def Ethernet(self , src: str, dst: str, type: int = 0x9000) : 
        return Ether(src=src, dst=dst , type=type)
    
    def Ip(self, src_ip: str, dst_ip: str, tos : int = 0, len: int = None, id: int = 1, frag: int = 0, ttl: int = 64, version: int = 4, proto ='ip'):
        return IP(src=src_ip, dst=dst_ip, tos=tos, len=len, id=id, frag=frag, ttl=ttl, version=version, proto=proto)
    
    def icmp(self ,type_name=0, code_name=0):
        return ICMP(type=type_name,code=code_name)
    
    def tcp(self ,sport, dport , seq=0, ack=0 , flags="S"):
        return TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) 
    
    def udp(self, sport, dport, length=None):
        return UDP(sport=sport, dport=dport, len=length)
    
    def data(self, payload):
        return Raw(load=payload)

    def craft_packet(self, ethernet_layer=None, ip_layer=None, transport_layer=None, data_layer=None):
        """Constructs a packet by stacking the provided layers."""
        layers = [layer for layer in [ethernet_layer, ip_layer, transport_layer, data_layer] if layer is not None]
        
        if layers:
            self.packet = layers[0]
            for layer in layers[1:]:
                self.packet = self.packet / layer
        else:
            self.packet = None

        return self.packet

    def display_packet(self):
        """Print the details of the crafted packet."""
        if self.packet:
            self.packet.show()
        else:
            print("No packet crafted yet.")

    # Layer 2: Send using sendp()
    def send_via_layer2(self):
        """Send the crafted packet at Layer 2 (Ethernet)."""
        if self.packet:
            sendp(self.packet)
        else:
            print("No packet crafted to send.")
        self.packet = None

    # Layer 3: Send using send()
    def send_via_layer3(self):
        """Send the crafted packet at Layer 3 (IP level)."""
        if self.packet:
            send(self.packet)
        else:
            print("No packet crafted to send.")
        self.packet = None

    # Layer 2: Send and Receive using srp()
    def send_receive_layer2(self):
        """Send and receive packets at Layer 2 (Ethernet)."""
        if self.packet:
            ans, unans = srp(self.packet, timeout=2)
            ans.show()
        else:
            print("No packet crafted to send.")
        self.packet = None

    # Layer 3: Send and Receive using sr()
    def send_receive_layer3(self):
        """Send and receive packets at Layer 3 (IP level)."""
        if self.packet:
            ans, unans = sr(self.packet, timeout=2)
            ans.show()
        else:
            print("No packet crafted to send.")

        self.packet = None
    
    # Layer 2: Send packets quickly using sendpfast()
    def send_fast_layer2(self):
        """Fast send at Layer 2 (Ethernet), useful for flooding."""
        if self.packet:
            sendpfast(self.packet)
        else:
            print("No packet crafted to send.")
        self.packet = None

class PacketCrafterApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Crafter")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("""
            background-color: #2A363B; 
            color: #FFFFFF; 
            font-family: Arial, sans-serif;
        """)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        
        # Create a QStackedWidget to handle page transitions
        self.stacked_widget = QStackedWidget()
        self.layout.addWidget(self.stacked_widget)
        
        # Initialize pages
        self.init_pages()

        # Navigation buttons
        self.init_navigation_buttons()
        
        # Set initial page
        self.stacked_widget.setCurrentIndex(0)

    def init_pages(self):
        # Page 1: Ethernet Information (Ethernet Layer)
        self.page1 = QWidget()
        self.page1_layout = QVBoxLayout()
        self.page1.setLayout(self.page1_layout)

        self.page1_layout.addWidget(self.create_header("Ethernet Layer"))

        # Ethernet Form
        self.ethernet_form_layout = QFormLayout()
        self.ethernet_form_layout.setLabelAlignment(Qt.AlignRight)
        self.ethernet_form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # Ethernet Source Input
        self.ether_src_input = QLineEdit()
        self.ether_src_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Ethernet Source:", self.ether_src_input, self.ethernet_form_layout)

        # Ethernet Destination Input
        self.ether_dst_input = QLineEdit()
        self.ether_dst_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Ethernet Destination:", self.ether_dst_input, self.ethernet_form_layout)

        # Ethernet Type ComboBox (Dynamic from ether_types.values)
        self.ether_type_combo = QComboBox()
        self.ether_type_combo.addItems(sorted(PacketCrafter.ether_types.values()))
        self.ether_type_combo.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.ether_type_combo.setFixedWidth(300)  # Adjust width as needed

        self.add_form_row("Ethernet Type:", self.ether_type_combo, self.ethernet_form_layout)

        self.page1_layout.addLayout(self.ethernet_form_layout)
        
        # Page 2: IP Information (IP Layer)
        self.page2 = QWidget()
        self.page2_layout = QVBoxLayout()
        self.page2.setLayout(self.page2_layout)

        self.page2_layout.addWidget(self.create_header("IP Layer"))

        # IP Form
        self.ip_form_layout = QFormLayout()
        self.ip_form_layout.setLabelAlignment(Qt.AlignRight)
        self.ip_form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # IP Source Input
        self.ip_src_input = QLineEdit()
        self.ip_src_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("IP Source:", self.ip_src_input, self.ip_form_layout)

        # IP Destination Input
        self.ip_dst_input = QLineEdit()
        self.ip_dst_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("IP Destination:", self.ip_dst_input, self.ip_form_layout)

        # ToS Input
        self.ip_tos_input = QLineEdit("0")
        self.ip_tos_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("ToS:", self.ip_tos_input, self.ip_form_layout)

        # Length Input
        self.ip_len_input = QLineEdit("None")
        self.ip_len_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Length:", self.ip_len_input, self.ip_form_layout)

        # ID Input
        self.ip_id_input = QLineEdit("1")
        self.ip_id_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("ID:", self.ip_id_input, self.ip_form_layout)

        # Fragment Offset Input
        self.ip_frag_input = QLineEdit("0")
        self.ip_frag_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Fragment Offset:", self.ip_frag_input, self.ip_form_layout)

        # TTL Input
        self.ip_ttl_input = QLineEdit("64")
        self.ip_ttl_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("TTL:", self.ip_ttl_input, self.ip_form_layout)

        # Version Input
        self.ip_version_input = QLineEdit("4")
        self.ip_version_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Version:", self.ip_version_input, self.ip_form_layout)

        # Protocol ComboBox (Dynamic from ip_protocols.values)
        self.ip_proto_combo = QComboBox()
        self.ip_proto_combo.addItems(sorted(PacketCrafter.ip_protocols.values()))
        self.ip_proto_combo.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.ip_proto_combo.setFixedWidth(300)  # Adjust width as needed

        self.add_form_row("Protocol:", self.ip_proto_combo, self.ip_form_layout)

        self.page2_layout.addLayout(self.ip_form_layout)
        
        # Page 3: Transport Layer Selection
        self.page3 = QWidget()
        self.page3_layout = QVBoxLayout()
        self.page3.setLayout(self.page3_layout)

        self.page3_layout.addWidget(self.create_header("Select Transport Layer Protocol"))

        # Protocol Buttons
        self.tcp_button = QPushButton("TCP")
        self.udp_button = QPushButton("UDP")
        self.icmp_button = QPushButton("ICMP")

        button_style = """
            padding: 10px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
            font-size: 14px;
        """
        self.tcp_button.setStyleSheet(button_style)
        self.udp_button.setStyleSheet(button_style)
        self.icmp_button.setStyleSheet(button_style)

        self.tcp_button.clicked.connect(lambda: self.show_protocol_page("TCP"))
        self.udp_button.clicked.connect(lambda: self.show_protocol_page("UDP"))
        self.icmp_button.clicked.connect(lambda: self.show_protocol_page("ICMP"))

        self.page3_layout.addWidget(self.tcp_button)
        self.page3_layout.addWidget(self.udp_button)
        self.page3_layout.addWidget(self.icmp_button)

        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.page1)
        self.stacked_widget.addWidget(self.page2)
        self.stacked_widget.addWidget(self.page3)
        self.create_data_page()

    def show_protocol_page(self, protocol):
        """Show the selected protocol page and remove any existing protocol pages."""
        
        # Define the protocol pages in a dictionary
        pages = {
            'TCP': 'tcp_page',
            'UDP': 'udp_page',
            'ICMP': 'icmp_page'
        }
        
        # Check if self.page4 exists and delete it
        if hasattr(self, 'page4'):
            page4 = getattr(self, 'page4', None)
            if page4:
                self.stacked_widget.removeWidget(page4)
                page4.deleteLater()
                setattr(self, 'page4', None)
 
        # Get the page to show
        current_page_attr = pages.get(protocol, None)
        
        if current_page_attr:
            # Iterate through all protocol pages
            for key, attr in pages.items():
                if key != protocol:
                    # Remove pages that are not the current one
                    page = getattr(self, attr, None)
                    if page:
                        self.stacked_widget.removeWidget(page)
                        # Optionally delete the page if it's not needed anymore
                        page.deleteLater()
                        setattr(self, attr, None)


            # Create and add the current page if it does not exist
            current_page = getattr(self, current_page_attr, None)
            if not current_page:
                create_page = getattr(self, f'create_{protocol.lower()}_page')
                current_page = create_page()
                setattr(self, current_page_attr, current_page)
                self.stacked_widget.addWidget(current_page)
            
            self.create_data_page()
            # Set the current page widget
            self.stacked_widget.setCurrentWidget(current_page)
        else:
            print(f"Protocol page creation method not found for {protocol}")

    def create_tcp_page(self):
        """Create the TCP page layout."""
        page = QWidget()
        layout = QVBoxLayout()
        page.setLayout(layout)
        
        layout.addWidget(self.create_header("TCP Layer"))

        # TCP Form
        tcp_form_layout = QFormLayout()
        tcp_form_layout.setLabelAlignment(Qt.AlignRight)
        tcp_form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # TCP Source Port Input
        self.tcp_src_port_input = QLineEdit()
        self.tcp_src_port_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Source Port:", self.tcp_src_port_input, tcp_form_layout)

        # TCP Destination Port Input
        self.tcp_dst_port_input = QLineEdit()
        self.tcp_dst_port_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Destination Port:", self.tcp_dst_port_input, tcp_form_layout)

        # TCP Sequence Number Input
        self.tcp_seq_input = QLineEdit("0")
        self.tcp_seq_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Sequence Number:", self.tcp_seq_input, tcp_form_layout)

        # TCP Acknowledgement Number Input
        self.tcp_ack_input = QLineEdit("0")
        self.tcp_ack_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Acknowledgement Number:", self.tcp_ack_input, tcp_form_layout)

        # TCP Flags Input
        self.tcp_flags_input = QLineEdit()
        self.tcp_flags_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Flags:", self.tcp_flags_input, tcp_form_layout)

        layout.addLayout(tcp_form_layout)
        return page

    def create_udp_page(self):
        """Create the UDP page layout."""
        page = QWidget()
        layout = QVBoxLayout()
        page.setLayout(layout)
        
        layout.addWidget(self.create_header("UDP Layer"))

        # UDP Form
        udp_form_layout = QFormLayout()
        udp_form_layout.setLabelAlignment(Qt.AlignRight)
        udp_form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # UDP Source Port Input
        self.udp_src_port_input = QLineEdit()
        self.udp_src_port_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Source Port:", self.udp_src_port_input, udp_form_layout)

        # UDP Destination Port Input
        self.udp_dst_port_input = QLineEdit()
        self.udp_dst_port_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Destination Port:", self.udp_dst_port_input, udp_form_layout)

        # UDP Length Input
        self.udp_length_input = QLineEdit()
        self.udp_length_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.add_form_row("Length:", self.udp_length_input, udp_form_layout)


        layout.addLayout(udp_form_layout)
        return page

    def create_icmp_page(self):
        """Create the ICMP page layout."""
        page = QWidget()
        layout = QVBoxLayout()
        page.setLayout(layout)
        
        layout.addWidget(self.create_header("ICMP Layer"))

        # ICMP Type Combobox
        self.icmp_type_combobox = QComboBox()
        self.icmp_type_combobox.setStyleSheet("""
            padding: 4px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.icmp_type_combobox.setFixedWidth(300)  # Adjust width as needed
        
        # Populate ICMP Type Combobox
        for type_name, type_info in PacketCrafter.icmp_types_and_codes.items():
            self.icmp_type_combobox.addItem(type_name, type_info["type"])

        # ICMP Code Combobox
        self.icmp_code_combobox = QComboBox()
        self.icmp_code_combobox.setStyleSheet("""
            padding: 4px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.icmp_code_combobox.setFixedWidth(300)  # Adjust width as needed
        
        # Populate ICMP Code Combobox based on selected ICMP Type
        self.icmp_type_combobox.currentIndexChanged.connect(self.update_icmp_code_combobox)
        
        # Layout for ICMP Type and Code
        icmp_layout = QFormLayout()
        icmp_layout.setLabelAlignment(Qt.AlignRight)
        icmp_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        icmp_layout.addRow(QLabel("Type:"), self.icmp_type_combobox)
        icmp_layout.addRow(QLabel("Code:"), self.icmp_code_combobox)

        layout.addLayout(icmp_layout)
        return page

    def create_data_page(self ):

        self.page4 = QWidget()
        self.page4_layout = QVBoxLayout()
        self.page4.setLayout(self.page4_layout)

        self.page4_layout.addWidget(self.create_header("Data Layer"))

        self.data_form_layout = QFormLayout()
        self.data_form_layout.setLabelAlignment(Qt.AlignRight)
        self.data_form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        self.payload = QTextEdit()
        self.payload.setStyleSheet("""
            padding: 8px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.payload.setPlaceholderText("Enter payload here...")

        self.add_form_row("Payload:", self.payload, self.data_form_layout)

        self.page4_layout.addLayout(self.data_form_layout)

        self.stacked_widget.addWidget(self.page4)

    def update_icmp_code_combobox(self):
        """Update the ICMP Code combobox based on the selected ICMP Type."""
        selected_type_name = self.icmp_type_combobox.currentText()
        type_info = PacketCrafter.icmp_types_and_codes.get(selected_type_name, {})
        
        self.icmp_code_combobox.clear()
        
        if isinstance(type_info, dict):
            if "codes" in type_info:
                for code_name in type_info["codes"]:
                    self.icmp_code_combobox.addItem(code_name)
            else:
                self.icmp_code_combobox.addItem(str(type_info["code"]))
        else:
            # Handle case where type_info is not a dict (e.g., if it's an integer)
            self.icmp_code_combobox.addItem(f"Code: {type_info}")

        # Optionally set default or first item as selected
        self.icmp_code_combobox.setCurrentIndex(0)

    def add_form_row(self, label_text, widget, layout):
        """Add a row to a form layout with a label and a widget."""
        label = QLabel(label_text)
        label.setStyleSheet("""
            color: #FFFFFF;
        """)
        layout.addRow(label, widget)

    def create_header(self, text):
        """Create a styled header widget."""
        header = QLabel(text)
        header.setStyleSheet("""
            color: #4CAF50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
        """)
        return header
    

    def init_navigation_buttons(self):
        """Initialize navigation buttons at the bottom of the main layout."""
        self.navigation_layout = QHBoxLayout()
        self.layout.addLayout(self.navigation_layout)

        # Previous Button
        self.prev_button = QPushButton("Previous")
        self.prev_button.setStyleSheet("""
            padding: 10px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.prev_button.clicked.connect(self.go_prev)

        # Next Button
        self.next_button = QPushButton("Next")
        self.next_button.setStyleSheet("""
            padding: 10px;
            border: 1px solid #4CAF50;
            border-radius: 4px;
            background-color: #344953;
            color: #FFFFFF;
        """)
        self.next_button.clicked.connect(self.go_next)

        self.navigation_layout.addWidget(self.prev_button)
        self.navigation_layout.addWidget(self.next_button)

    def go_prev(self):
        """Handle the previous button click."""
        current_index = self.stacked_widget.currentIndex()
        if current_index > 0:
            self.stacked_widget.setCurrentIndex(current_index - 1)
            self.update_navigation_buttons()
    
    def go_next(self):
        """Handle the next button click."""
        current_index = self.stacked_widget.currentIndex()
        if current_index < self.stacked_widget.count() - 1:
            self.stacked_widget.setCurrentIndex(current_index + 1)
        self.update_navigation_buttons()
    
    def update_navigation_buttons(self):
        """Update the navigation buttons visibility based on the current page."""
        current_index = self.stacked_widget.currentIndex()

        # Disable the 'Previous' button on the first page
        self.prev_button.setEnabled(current_index > 0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = PacketCrafterApp()
    main_window.show()
    sys.exit(app.exec_())
