import socket
import struct
import textwrap
import time
import os
import threading
####

stop = True

class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

def main():
    mainMenu()

#Escuchar Trafico
def escucharTrafico(eth_opc, filtro):
    global stop

    filename = input("\n\tIngrese el nombre del archivo PCAP para guardar la lectura: ")
    filename += '.pcap'
    pcap = Pcap(str(filename))

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    cont = 0

    while True:
        if stop == True:
            break

        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # 8 para IPv4
        if eth_proto == 8 and eth_opc == None or eth_proto == 8 and eth_opc == 8 :
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)


            # 1 ICMP (Internet Control Message Protocol)

            if proto == 1 and filtro == None or  proto == 1 and filtro == 1:
                cont += 1
                print('\n\tTrama Ethernet: # ',cont)
                print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))
                print('\tPaquete IPv4:')
                print('\t\tVersion: {}, Longitud del encabezado: {}, TTL: {}'.format(version, header_length, ttl))
                print('\t\tProtocolo: {}, Fuente: {} Destino: {}'.format(proto, src, target))
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\t    Paquete ICMP: ')
                print('\t\tTipo: {}, Codigo: {}, Checksum: {}'.format(icmp_type,code, checksum))
                print('\t\tDatos:')
                print(format_multi_line('\t\t* ', data))
                pcap.write(raw_data)
                print("\n\t=============================================================================")

            # 6 TCP (Transmission Control Protocol)
            elif proto == 6 and filtro == None or proto == 6 and filtro == 6:
                cont += 1
                print('\n\tTrama Ethernet: # ',cont)
                print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))
                print('\tPaquete IPv4:')
                print('\t\tVersion: {}, Longitud del encabezado: {}, TTL: {}'.format(version, header_length, ttl))
                print('\t\tProtocolo: {}, Fuente: {} Destino: {}'.format(proto, src, target))
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print('\t    Segmento TCP: ')
                print('\t\tPuerto de Origen: {}, Puerto Destino: {}'.format(src_port,dest_port))
                print('\t\tSecuencia: {}, Reconocimiento: {}'.format(sequence, acknowledgment))
                print('\t\tBanderas: ')
                print('\t\t\tURG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print('\t\t\tRST: {}, SYN: {}, FIN: {}'.format(flag_rst, flag_syn, flag_fin))
                pcap.write(raw_data)

                if len(data) > 0:
                    # HTTP (Hypertext Transfer Protocol)
                    if src_port == 80 or dest_port == 80:
                        print('\t\tDatos HTTP: ')
                        try:
                            http =  http_dec(data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print('\t\t\t * '+str(line))
                        except:
                            print(format_multi_line('\t\t\t * ', data))
                    else:
                        print('\t\tDatos TCP: ')
                        print(format_multi_line('\t\t\t * ', data))

                print("\n\t=============================================================================")

            # 17 UDP (User Datagram Protocol)
            elif proto == 17 and filtro == None or proto == 17 and filtro == 17:
                cont += 1
                print('\n\tTrama Ethernet: # ',cont)
                print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))

                src_port, dest_port, length, data = udp_segment(data)
                print('\t    Segmento UDP: ')
                print('\t\tPuerto de Origen: {}, Puerto Destino: {}, Longitud: {}'.format(src_port,dest_port,length,)+ ' bytes')
                pcap.write(raw_data)
                print("\n\t=============================================================================")

            # Otro IPv4
            else:
                if filtro == None:
                    cont += 1
                    print('\n\tTrama Ethernet: # ',cont)
                    print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))
                    print('\tPaquete IPv4:')
                    print('\t\tVersion: {}, Longitud del encabezado: {}, TTL: {}'.format(version, header_length, ttl))
                    print('\t\tProtocolo: {}, Fuente: {} Destino: {}'.format(proto, src, target))
                    print('\tOtro Protocolo IPv4:')
                    print(format_multi_line('\t\t * ',data))
                    pcap.write(raw_data)
                    print("\n\t=============================================================================")

        # 1544 para ARP
        elif eth_proto == 1544 and eth_opc == None or eth_proto == 1544 and eth_opc == 1544:
            cont += 1
            print('\n\tTrama Ethernet: # ',cont)
            print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))

            hardware_type, protocol_type, hardware_length, protocol_length, \
                operation, sender_mac_address, sender_ip_adress, \
                target_mac_address, target_ip_address, data = arp_packet(data)

            if socket.ntohs(protocol_type) == 8:
                protocol_type = 'iPv4 (0x0800)'
            if operation == 1:
                operation = 'Solicitud (1)'
            else:
                operation = 'Respuesta (2)'

            print('\t    Paquete ARP: ')
            print('\t\tTipo de Hardware: {}, Tipo de protocolo: {}'.format(hardware_type, protocol_type))
            print('\t\tLongitud del hardware: {}, Longitud del protocolo: {}'.format(hardware_length, protocol_length))
            print('\t\tOperacion: {}'.format(operation))
            print('\t\tMAC address origen: {},  IP origen: {}'.format(sender_mac_address, sender_ip_adress))
            print('\t\tMAC address destino: {}, IP destino: {}'.format(target_mac_address, target_ip_address))
            pcap.write(raw_data)
            print("\n\t=============================================================================")

        # 56710 para iPv6
        elif eth_proto == 56710 and eth_opc == None or eth_proto == 56710 and eth_opc == 56710:

            version, payload_length, proto, hop_limit, src, target, data = ipv6_packet(data)

            # 17 UDP (User Datagram Protocol) para IPv6
            if proto == 17 and filtro == None or proto == 17 and filtro == 17:
                cont += 1
                print('\n\tTrama Ethernet: # ',cont)
                print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))
                print('\tPaquete IPv6:')
                print('\t   Version: {}, Carga util: {}, Protocolo: {}'.format(version, payload_length, proto))
                print('\t   Limite de saltos: {}'.format(hop_limit))
                print('\t   Fuente:  {}'.format(src))
                print('\t   Destino: {}'.format(target))
                src_port, dest_port, length, data = udp_segment(data)
                print('\t    Segmento UDPv6: ')
                print('\t\tPuerto de Origen: {}, Puerto Destino: {}, Longitud: {}'.format(src_port,dest_port,length,)+ ' bytes')
                pcap.write(raw_data)
                print("\n\t=============================================================================")

            # 58 ICMPv6 (Internet Control Message Protocol) para IPv6
            elif proto == 58 and filtro == None or proto == 58 and filtro == 58:
                cont += 1
                print('\n\tTrama Ethernet: # ',cont)
                print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))
                print('\tPaquete IPv6:')
                print('\t   Version: {}, Carga util: {}, Protocolo: {}'.format(version, payload_length, proto))
                print('\t   Limite de saltos: {}'.format(hop_limit))
                print('\t   Fuente:  {}'.format(src))
                print('\t   Destino: {}'.format(target))
                icmp_type, code, checksum, data = icmp_packet(data)
                if icmp_type == 1:
                    icmp_type = 'Destino inalcanzable (1)'
                if code == 4:
                    code = 'Puerto inalcanzable (4)'
                print('\t    Paquete ICMPv6: ')
                print('\t\tTipo: {}, Codigo: {}, Checksum: {}'.format(icmp_type,code, checksum))
                print('\t\tDatos:')
                print(format_multi_line('\t\t* ', data))
                pcap.write(raw_data)
                print("\n\t=============================================================================")

            # Otro IPv6
            else:
                if filtro == None:
                    cont += 1
                    print('\n\tTrama Ethernet: # ',cont)
                    print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))
                    print('\tPaquete IPv6:')
                    print('\t   Version: {}, Carga util: {}, Protocolo: {}'.format(version, payload_length, proto))
                    print('\t   Limite de saltos: {}'.format(hop_limit))
                    print('\t   Fuente:  {}'.format(src))
                    print('\t   Destino: {}'.format(target))
                    print('\tOtro Protocolo IPv6:')
                    print(format_multi_line('\t\t * ',data))
                    pcap.write(raw_data)
                    print("\n\t=============================================================================")

        # Otro protocolo Ethernet
        elif eth_opc == None:
            cont += 1
            print('\n\tTrama Ethernet: # ',cont)
            print('\tMAC Fuente: {}, MAC Destino: {}, Ether type: {}'.format(src_mac, dest_mac, eth_proto))

            print('\t Datos Ethernet: \n')
            print(format_multi_line('\t * ',data))
            pcap.write(raw_data)
            print("\n\t=============================================================================")


    pcap.close()

#Funcion hilo activa el bucle de escucharTrafico()
def funcionHilo(eth_opc, filtro):
    global stop
    hilo = threading.Thread( target = escucharTrafico, args = (eth_opc, filtro,))
    hilo.start()
    input("")
    stop = True
    time.sleep(2)

#Filtrado por protocolo para IPv4
def filtrado_IPv4():
    global stop
    os.system("clear")
    print("\n\t* * Filtrado por protocolo para IPv4* *")
    print("\n\t1) Todos los protocolos de iPv4 ")
    print("\n\t2) ICMP")
    print("\n\t3) TCP")
    print("\n\t4) UDP")
    print("\n\t0) Regresar")
    opc = input ("\n\tIngrese una opcion: ")

    if opc.isdigit() == True:
        opc = int(opc)
        if opc == 1:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x0800), None)
        elif opc == 2:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x0800), 1)
        elif opc == 3:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x0800), 6)
        elif opc == 4:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x0800), 17)

        elif opc == 0:
            return
    else:
        print("\n\t(!) Seleccione una de las opciones del menu...")
        input("\n\tPresione < ENTER > para continuar...")

#Filtrado por protocolo para IPv6
def filtrado_IPv6():
    global stop
    os.system("clear")
    print("\n\t* * Filtrado por protocolo para IPv6* *")
    print("\n\t1) Todos los protocolos de iPv6 ")
    print("\n\t2) UDPv6")
    print("\n\t3) ICMPv6")
    print("\n\t0) Regresar")
    opc = input ("\n\tIngrese una opcion: ")

    if opc.isdigit() == True:
        opc = int(opc)
        if opc == 1:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x86DD), None)
        elif opc == 2:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x86DD), 17)
        elif opc == 3:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x86DD), 58)

        elif opc == 0:
            return
    else:
        print("\n\t(!) Seleccione una de las opciones del menu...")
        input("\n\tPresione < ENTER > para continuar...")


#Filtrado por protocolo general
def filtrado():
    global stop
    os.system("clear")
    print("\n\t* * Filtrado por protocolo * *")
    print("\n\t1) iPv4 (0x0800)")
    print("\n\t2) ARP  (0x0806)")
    print("\n\t3) iPv6 (0x86DD)")
    print("\n\t0) Regresar")
    opc = input ("\n\tIngrese una opcion: ")
    if opc.isdigit() == True:
        opc = int(opc)
        if opc == 1:
            filtrado_IPv4()
        elif opc == 2:
            stop = False
            while stop == False:
                funcionHilo(socket.ntohs(0x0806), None)
        elif opc == 3:
            filtrado_IPv6()
        elif opc == 0:
            return
    else:
        print("\n\t(!) Seleccione una de las opciones del menu...")
        input("\n\tPresione < ENTER > para continuar...")

#Menu General
def mainMenu():
    while True:
        #os.system("clear")
        print("\n\t\t* * * S N I F F E R * * * ")
        print("\n\t1) Escuchar trafico en red (Presiona < ENTER > para detener...)")
        print("\n\t2) Filtrar por protocolo")
        print("\n\t0) Salir")

        opc = input ("\n\tIngrese una opcion: ")
        if opc.isdigit() == True:
            opc = int(opc)
            if opc == 1:
                global stop
                stop = False
                while stop == False:
                    funcionHilo(None,None)
            elif opc == 2:
                filtrado()
            elif opc == 3:
                os.system("clear")
                return
            elif opc == 4:
                pass
            elif opc == 0:
                break
        else:
            print("\n\t(!) Seleccione una de las opciones del menu...")
            input("\n\tPresione < ENTER > para continuar...")


# Desempaquetado de la trama ethernet
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Regresar correctamente formateada la MAC Address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#Regresar correctamente formateada la direccion IPv6
def ipv6(bytes_addr):
    addr_doc = ''
    addr = ''
    i = 0
    flag_u = False
    flag_d = False

    bytes_str = map('{:02x}'.format, bytes_addr)

    for byte in bytes_str:
        addr_doc += byte
        if i % 2 and i < 15:
            addr_doc += ':'
        i += 1
    i = 0
    for byte in addr_doc:

        if byte != '0':

            if byte == ':':
                if flag_u == False and flag_d == False:
                    addr += byte
                    flag_u = True

                elif flag_u == True and flag_d == False:
                    addr += byte
                    flag_d = True
            else:
                addr += byte
                flag_u = False
                flag_d = False

        elif i > 0 and addr_doc[i-1] != '0' and addr_doc[i-1] != ':':
            addr += byte

        i += 1
    return addr


#Desempaquetado de la IPv4
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Regresar correctamente formateada la direccion IPv4
def ipv4(addr):
    return '.'.join(map(str, addr))

#Desempaquetado de la IPv6
def ipv6_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    payload_length, proto, hop_limit, src, target = struct.unpack('! 4x H B B 16s 16s', data[:40])
    return version, payload_length, proto, hop_limit, ipv6(src), ipv6(target), data[40:]


#Desempaquetado del ICMP
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Desempaquetado del segmento TCP
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H',  data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Desempaquetado del segmento UDP
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, size, data[8:]

#Desempaquetado del ARP
def arp_packet(data):
    hardware_type, protocol_type, hardware_length, protocol_length, \
        operation, sender_mac_address, sender_ip_adress, \
        target_mac_address, target_ip_address = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])

    return hardware_type, protocol_type, hardware_length, protocol_length, \
        operation, get_mac_addr(sender_mac_address), ipv4(sender_ip_adress), \
        get_mac_addr(target_mac_address), ipv4(target_ip_address), data[28:]


#Decodificacion de HTTP
def http_dec(data):
    try:
        data = data.decode('utf-8')
    except:
        data = data
    return data

#Formato de datos multilinea
def format_multi_line(prefix, string, size=62):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
