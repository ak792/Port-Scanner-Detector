import sys
import socket
import datetime
import locale


#Scans for open ports on a target host
def usage():
    #Prints the correct command to execute the program
    print 'Usage: python', sys.argv[0], 'target'


def get_args():
    #gets command line arguments
    if len(sys.argv) != 2:
        usage()
        sys.exit()

    try:
        #converts the target's hostname to its IP address
        target_host = socket.gethostbyname(sys.argv[1])
    except socket.gaierror:
        print 'Invalid host'
        sys.exit()

    return target_host


def probe_ports(target, min_port_num, max_port_num, evasive):
    #iterates through ports on a target and tries to establish a socket connection
    #records the ports to which a connection could be established
    open_ports = []

    #typically, will iterate from port 0 to port 65535
    #if evasive mode is enabled, will iterate from port 65535 down to port 0
        #to avoid detection by psdetect.py
    if not evasive:
        port_nums_rng = range(min_port_num, max_port_num + 1)
    else:
        port_nums_rng = range(max_port_num, min_port_num - 1, -1)

    for curr_port_num in port_nums_rng:
        try:
            #record if a connection to curr_port_num can be successfully established
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect( (target, curr_port_num) )
            open_ports.append( (curr_port_num, socket.getservbyport(curr_port_num, 'tcp')) )
            s.close()

        except socket.error:
            #if a connection could not be established, do nothing
            pass

    #return ports in sorted order
    if evasive:
        open_ports.sort()

    return open_ports


def time_to_execute(function, *args):
    #wrapper function that times how long it takes a function to execute
    #time_to_execute's arguments are the function to be executed and that function's arguments

    start_time = datetime.datetime.now()

    #res contains the output of the function
    res = function(*args)

    end_time = datetime.datetime.now()
    duration_seconds = (end_time - start_time).total_seconds()
    return duration_seconds, res


def print_output(duration_seconds, open_ports, scan_rate):
    #prints the results of the port scan

    locale.setlocale(locale.LC_ALL, 'en_US.utf8')
    print
    print 'Statistics'
    print '\tNum. Ports Open: ' + str(len(open_ports))
    print '\tScan Duration: ' + str( locale.format('%.2f', duration_seconds, grouping=True) ) + ' seconds'
    print '\tScan Rate: ' + str( locale.format('%.2f', scan_rate, grouping=True) ) + ' ports scanned per second'
    print

    print 'Open Ports'
    for open_port in open_ports:
        print '\t' + str(open_port[0]) + ': ' + str(open_port[1])


def run(evasive=False):
    #Runs the program
    #By default, evasive mode is disabled
    try:
        min_port_num = 0
        max_port_num = 65535

        #gets the specified target's IP address
        target_host = get_args()

        #scans the target's ports
        duration_seconds, open_ports = time_to_execute(probe_ports, target_host, min_port_num, max_port_num, evasive)

        #prints the results
        scan_rate = max_port_num / duration_seconds
        print_output(duration_seconds, open_ports, scan_rate)
    except KeyboardInterrupt:
        print '\nTerminating program'
    except EOFError:
        print 'Terminating program'