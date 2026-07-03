from argparse import ArgumentParser
from scapy.all import IP, TCP, UDP, ICMP, send, sr1
import socket

# aggresive scanning function
def grab_banner(target, port):
  try:
    # define socket format
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # if no response within 1 second, then->
    sock.settimeout(1)
    # scan port
    sock.connect_ex((target, port))
    # receive banner from the socket
    banner = sock.recv(1024).decode().strip()
    # close tcp connection
    sock.close()

    return banner
  
  except Exception:
    return None

def scan(ports: list, target, verbose=False, scan_type='tcp_connect', aggressive=False):
  # scan the ports array and classify open, closed or filtered
  results = list()
  if scan_type == 'tcp_connect':
    for port in ports:
      # define socket format
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(1) # if no response within 1 second,then->

      # scan port
      try:
        result = sock.connect_ex((target, port))

        if result == 0:
          state = 'OPEN'
        else:
          state = 'CLOSED'

      # if no response within 1 second, then->
      except socket.timeout:
        state = 'FILTERED'

      # close TCP connection
      finally:
        sock.close()

      if verbose:
        print(f"Port {port}: {state}")
        if state == 'OPEN' and aggressive:
          banner = grab_banner(target, port)
          print(f" - {banner}")
        else:
          print()
      elif state == 'OPEN':
        print(f"Port {port}: OPEN")
        if aggressive:
          banner = grab_banner(target, port)
          print(f"Port {port}: OPEN - {banner}")
        else:
          print()

      
      results.append({'port': port, 'state': state})  

    return results
  

top_1000_ports = [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 161, 179, 199, 211, 212, 222, 254, 255, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1007, 1009, 1052, 1100, 1102, 1104, 1106, 1112, 1113, 1114, 1117, 1119, 1121, 1123, 1126, 1130, 1131, 1137, 1138, 1141, 1145, 1147, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1512, 1527, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1900, 1914, 1935, 1971, 1972, 1974, 1984, 1998, 2000, 2002, 2005, 2007, 2009, 2017, 2020, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2107, 2110, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2628, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2920, 2967, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3386, 3389, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4127, 4128, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4949, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012, 5013, 5014, 5015, 5020, 5021, 5022, 5025, 5026, 5027, 5028, 5029, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5803, 5804, 5805, 5806, 5807, 5808, 5809, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8194, 8200, 8222, 8254, 8290, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9618, 9666, 9876, 9877, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10628, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30951, 31038, 31337, 32768, 32769, 32771, 32774, 32815, 33354, 33899, 34571, 34573, 35500, 36001, 36865, 37300, 37301, 37302, 37303, 37304, 37305, 37306, 37307, 37308, 37309, 37310, 37388, 37456, 37457, 37601, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44900, 45100, 48080, 49152, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389]
top_100_ports = [80, 443, 22, 3306, 5432, 8080, 8443, 21, 25, 110, 143, 53, 139, 445, 1433, 3389, 5985, 5986, 9090, 8000]

def main():
  # instantiate parser object
  parser = ArgumentParser(description='Port Scanner')

  parser.add_argument('target', help='Target IP or hostname')
  parser.add_argument('-a', action='store_true', dest='all_ports', help='Scan all 65535 ports')
  parser.add_argument('-p', metavar='<PORTS>', dest='port_range', help='Port range or specific ports')
  parser.add_argument('-v', '--verbose', dest='v', action='store_true', help='Verbose output')
  parser.add_argument('-F', action='store_true', help='Fast mode (top 100 ports)')
  parser.add_argument('-sS', action='store_true', help='SYN scan')
  parser.add_argument('-sU', action='store_true', help='UDP scan')
  parser.add_argument('-sA', action='store_true', help='ACK scan')
  parser.add_argument('-A', action='store_true', help='Aggressive scan')

  args = parser.parse_args()

  # Determine scan type
  scan_type = 'tcp_connect'
  if args.sS:
    scan_type = 'syn'
  elif args.sU:
    scan_type = 'udp'
  elif args.sA:
    scan_type = 'ack'

  # Determine if aggressive
  is_aggressive = args.A

  if args.all_ports:
    all_ports = list(range(0, 65536))
    res = scan(all_ports, args.target, verbose=args.v, scan_type=scan_type, aggressive=is_aggressive)

  elif args.port_range and '-' in args.port_range:
    start, end = args.port_range.split('-')
    ports = list(range(int(start), int(end) + 1))
    res = scan(ports, args.target, verbose=args.v, scan_type=scan_type, aggressive=is_aggressive)

  elif args.port_range:
    port_strings = args.port_range.split(',')
    ports = list()
    for port_str in port_strings:
      port_int = int(port_str)
      ports.append(port_int)
    res = scan(ports, args.target, verbose=args.v, scan_type=scan_type, aggressive=is_aggressive)

  elif args.F:
    res = scan(top_100_ports, args.target, verbose=args.v, scan_type=scan_type, aggressive=is_aggressive)

  else:
    res = scan(top_1000_ports, args.target, verbose=args.v, scan_type=scan_type, aggressive=is_aggressive)
  
if __name__ == "__main__":
  main()