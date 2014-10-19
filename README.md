Port Scanner Implementations

Simple implementations of port scanners. portscan.py scans ports in increasing order. portscantoo.py scans ports in decreasing order. portscan.py and portscantoo.py both are dependent on port_scanner.py. Please ensure that they are in the same folder.

Port Scanner Detector

psdetect.py detects a port scanner that establishes connections to 15+ consecutive ports in consecutive order within a 5 second window. 

The program maintains a dictionary of deques to keep track of the ports that remote hosts have recently connected to. The keys of the dictionary are IP addresses of remote hosts. The values are a deques of {port_num, timestamp} dicts that maintain, in order, the list of the most recent consecutive ports that the corresponding host has consecutively connected to. Further, the difference between the first and the last port connected to will never exceed 5.

Arriving packets are first inspected for the SYN flag to determine if the source is establishing a connection. If so, the program will insert a record of that connection into the dictionary of deques and will output if 15 or more consecutive ports were consecutively connected to within the last 5 seconds. During the insertion, the program will clear records of connections from that host that are more than 5 seconds older than the most recent connection.

Note that this will maintain at least one data point of all hosts that ever connected. This will result in overflow if a very large number of hosts connect to the machine running the detector.