import getopt
import sys
import socket


# parse the initial arguments
# returns the port range
def parse_arg():
    try:
        argv = sys.argv[2:]
        opts, args = getopt.getopt(argv, 'p:')
        if len(args) == 0:
            if len(opts) == 0:
                port_start = 1
                port_end = 1025
                return [port_start, port_end]
            elif len(opts) == 1:
                ports = opts[0][1].split(":")
                port_start = int(ports[0])
                port_end = int(ports[1]) + 1
                return [port_start, port_end]
        else:
            print('usage: portscanner.py hostname [-p #:#]')
            sys.exit(2)
    except getopt.GetoptError:
        print('usage: portscanner.py hostname [-p #:#]')
        sys.exit(2)


# perform port scanning
# returns one value that indicates its state and another for the port number
def scan_port(host_name, port_cur):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        ret = s.connect_ex((host_name, port_cur))
        s.close()
        if ret:
            return [0, port_cur]
        else:
            port_name = {20:'FTP', 21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS', 67:'DHCP',
                         68:'DHCP', 69:'TFTP', 80:'HTTP', 110:'POP3', 123:'NTP', 137:'NetBIOS', 138:'NetBIOS',
                         139: 'NetBIOS', 143:'IMAP', 161:'SNMP', 162:'SNMP', 179:'BGP', 389:'LDAP', 443:'HTTPS',
                         636:'LDAPS', 989:'FTP(TLS/SSL)', 990:'FTP(TLS/SSL)'}
            service = port_name[port_cur]
            return [1, port_cur, service]
    except socket.error:
        return [0, port_cur]


if __name__ == '__main__':
    port_range = parse_arg()
    host = socket.gethostbyname(sys.argv[1])

    print("PORT" + '\t' + "STATE" + '\t' + "SERVICE")

    for port in range(port_range[0], port_range[1]):
        result = scan_port(host, port)
        if result[0]:
            output = str(port) + "/tcp" + '\t' + "open" + '\t' + str(result[2])
            print(output)
        else:
            pass

