import wmi
wmi_obj = wmi.WMI()
wireless_interfaces = [interface.Name for interface in wmi_obj.Win32_NetworkAdapter() if 'Wi-Fi' in interface.Name]
print(wireless_interfaces)
