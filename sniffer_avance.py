from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
import argparse

# Configuration des arguments de ligne de commande
parser = argparse.ArgumentParser(description="Sniffer réseau avancé en Python avec Scapy")
parser.add_argument("-i", "--interface", type=str, help="Interface réseau à utiliser pour la capture", required=True)
parser.add_argument("-f", "--filter", type=str, help="Filtre de capture (ex: 'tcp', 'udp', 'icmp')", default="")
parser.add_argument("-o", "--output", type=str, help="Fichier de sortie pour les paquets capturés", default="captured_packets.pcap")
parser.add_argument("-c", "--count", type=int, help="Nombre de paquets à capturer (0 pour illimité)", default=0)
args = parser.parse_args()

# Variables pour les statistiques
packet_count = 0
protocol_counts = defaultdict(int)
src_ip_counts = defaultdict(int)
dst_ip_counts = defaultdict(int)

# Fonction de rappel pour la capture des paquets
def packet_callback(packet):
    global packet_count

    # Compter les paquets capturés
    packet_count += 1

    # Compter les paquets par protocole
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol_counts[ip_layer.proto] += 1
        src_ip_counts[ip_layer.src] += 1
        dst_ip_counts[ip_layer.dst] += 1

        # Afficher des informations détaillées pour chaque paquet capturé
        print(f"[{packet_count}] {ip_layer.src} -> {ip_layer.dst} (Protocole: {ip_layer.proto})")

        if packet.haslayer(TCP):
            print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"    ICMP Type: {packet[ICMP].type}")

# Capture des paquets
print(f"Capture des paquets sur l'interface {args.interface} avec le filtre '{args.filter}'...")
packets = sniff(iface=args.interface, filter=args.filter, prn=packet_callback, count=args.count)

# Enregistrer les paquets dans un fichier
print(f"Enregistrement des paquets capturés dans le fichier {args.output}...")
wrpcap(args.output, packets)

# Afficher les statistiques de capture
print("\nStatistiques de capture :")
print(f"Nombre total de paquets capturés : {packet_count}")
print("Répartition des protocoles :")
for proto, count in protocol_counts.items():
    print(f"  Protocole {proto} : {count} paquets")

print("Adresses IP sources :")
for ip, count in src_ip_counts.items():
    print(f"  {ip} : {count} paquets")

print("Adresses IP destinations :")
for ip, count in dst_ip_counts.items():
    print(f"  {ip} : {count} paquets")

print("Sniffer terminé.")
