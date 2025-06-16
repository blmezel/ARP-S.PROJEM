import pyshark
import os
from collections import defaultdict

PCAP_FILE = 'captures/arp_spoof_capture.pcapng'
OUTPUT_DIR = 'pyshark_output'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'arp_spoof_result_2.txt')

def detect_arp_spoofing(pcap_file):
    # Çıktı klasörü hazır mı?
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"📁 {OUTPUT_DIR} klasörü oluşturuldu.")
    else:
        print(f"📁 {OUTPUT_DIR} klasörü zaten var.")

    print(f"📦 PCAP dosyası: {os.path.abspath(pcap_file)}")
    print(f"📝 Çıktı dosyası: {os.path.abspath(OUTPUT_FILE)}\n")

    try:
        capture = pyshark.FileCapture(pcap_file, use_json=True)  # Artık filtre yok
    except Exception as e:
        print(f"❌ PCAP dosyası açılamadı: {e}")
        return

    ip_mac_map = defaultdict(set)
    total_arp = 0

    try:
        with open(OUTPUT_FILE, 'w') as f:
            f.write("🎯 ARP Spoofing Analizi Sonuçları (Kayıt #2):\n\n")
            for pkt in capture:
                try:
                    if 'ARP' in pkt:
                        ip = pkt.arp.src_proto_ipv4
                        mac = pkt.arp.hw_src
                        ip_mac_map[ip].add(mac)
                        total_arp += 1
                except AttributeError:
                    continue

            if total_arp == 0:
                f.write("⚠️ Hiç ARP paketi bulunamadı.\n")

            for ip, macs in ip_mac_map.items():
                if len(macs) > 1:
                    f.write(f"[!] {ip} adresi için birden fazla MAC tespit edildi:\n")
                    for mac in macs:
                        f.write(f"    ↪ {mac}\n")
                    f.write("-" * 40 + "\n")
                else:
                    f.write(f"[✓] {ip} → {list(macs)[0]}\n")

        print(f"✅ {total_arp} ARP paketi işlendi ve çıktı dosyaya yazıldı.")
        print(f"📄 Sonuç başarıyla kaydedildi: {OUTPUT_FILE}")

    except Exception as e:
        print(f"🚨 Yazma sırasında hata: {e}")

    capture.close()

if __name__ == "__main__":
    detect_arp_spoofing(PCAP_FILE)



