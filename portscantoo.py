import port_scanner

#Scans for open ports on a target host
#Scans ports in reverse order to avoid detection by psdetect.py
port_scanner.run(True)
