import pyshark

PCAP_FILE = 'captures/arp_spoof_capture.pcapng'

def analyze_packets(pcap_file):
    capture = pyshark.FileCapture(pcap_file)  # filtresiz

    print("Analiz başladı, bu biraz sürebilir...")

    with open('pyshark_output/full_analysis.txt', 'w') as f:
        for packet in capture:
            try:
                f.write(f"Zaman: {packet.sniff_time}\n")
                f.write(f"Paket No: {packet.number}\n")
                f.write(f"Katmanlar: {', '.join(layer.layer_name for layer in packet.layers)}\n")

                if 'arp' in packet:
                    arp = packet.arp
                    f.write("== ARP Detayları ==\n")
                    f.write(f"Sender MAC: {arp.hw_src}\n")
                    f.write(f"Sender IP: {arp.src_proto_ipv4}\n")
                    f.write(f"Target MAC: {arp.hw_dst}\n")
                    f.write(f"Target IP: {arp.dst_proto_ipv4}\n")

                if 'ip' in packet:
                    ip = packet.ip
                    f.write("== IP Detayları ==\n")
                    f.write(f"Kaynak IP: {ip.src}\n")
                    f.write(f"Hedef IP: {ip.dst}\n")
                    f.write(f"Protokol: {ip.proto}\n")

                if 'tcp' in packet:
                    tcp = packet.tcp
                    f.write("== TCP Detayları ==\n")
                    f.write(f"Kaynak Port: {tcp.srcport}\n")
                    f.write(f"Hedef Port: {tcp.dstport}\n")

                if 'udp' in packet:
                    udp = packet.udp
                    f.write("== UDP Detayları ==\n")
                    f.write(f"Kaynak Port: {udp.srcport}\n")
                    f.write(f"Hedef Port: {udp.dstport}\n")

                f.write("-" * 40 + "\n")
            except AttributeError:
                continue

    capture.close()
    print("Analiz tamamlandı, çıktı pyshark_output/full_analysis.txt dosyasında.")

if __name__ == "__main__":
    analyze_packets(PCAP_FILE)


