import sys
import psutil
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QMenuBar,
    QAction, QStatusBar, QHBoxLayout, QFrame, QScrollArea, QRadioButton, QButtonGroup, QPushButton
)
from PyQt5.QtCore import Qt
import socket
import webbrowser

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize selected interface variable
        self.selected_interface = None
        
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
        
        # Open Action
        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        # Export as CSV Action
        export_csv_action = QAction("Export as CSV", self)
        export_csv_action.triggered.connect(self.export_as_csv)
        file_menu.addAction(export_csv_action)
        
        # Export as JSON Action
        export_json_action = QAction("Export as JSON", self)
        export_json_action.triggered.connect(self.export_as_json)
        file_menu.addAction(export_json_action)
        
        # Exit Action
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
        self.next_button.setFixedSize(100, 40)  # Set size for consistency
        
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
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)  # Disable the horizontal scrollbar
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
                if address.family == socket.AF_INET:  # Use socket.AF_INET for IPv4
                    ip_label = QLabel(f"IP: {address.address}", self)
                    ip_label.setStyleSheet("font-size: 16px; color: #AAAAAA; margin-left: 20px;")
                    interface_layout.addWidget(ip_label)
                elif address.family == psutil.AF_LINK:  # Use psutil.AF_LINK for MAC addresses on Windows
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
        
        # Create a new central widget and layout for the next page
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        

        
    def open_file(self): 
        # Placeholder for file open logic
        pass

    def export_as_csv(self):
        # Placeholder for exporting as CSV logic
        pass

    def export_as_json(self):
        # Placeholder for exporting as JSON logic
        pass

    def open_documentation(self):
        # Open the documentation link in the default web browser
        url = "https://example.com/documentation"  # Replace with your documentation URL
        webbrowser.open(url)
    
    def show_about_dialog(self):
        about_label = QLabel("Windows Sniffer App\nVersion 0.1\nDeveloped by [Your Name]", self)
        about_label.setWindowTitle("About")
        about_label.setFixedSize(300, 100)
        about_label.show()

# Main function to run the app
if __name__ == "__main__":
    app = QApplication(sys.argv)

    main_window = SnifferApp()
    main_window.show()
    sys.exit(app.exec_())
