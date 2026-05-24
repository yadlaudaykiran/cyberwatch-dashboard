from scapy.all import sniff
import time

running = False


def packet_callback(packet):

    global running

    if not running:
        return

    if packet.haslayer("IP"):

        src = packet["IP"].src
        dst = packet["IP"].dst

        log = f"{src} -> {dst}"

        print(log)

        with open("logs/packets.txt", "a") as f:
            f.write(log + "\n")


def start_sniffer():

    print("✅ Sniffer Thread Running")

    sniff(
        prn=packet_callback,
        store=False
    )