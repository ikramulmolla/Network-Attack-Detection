from scapy.all import ARP, sniff
from datetime import datetime
from colorama import init, Fore, Style
import threading

# Initialize colorama
init()

# Global variable to control sniffing
sniffing_active = False

def arp_spoof_detect(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # 1 for who-has (request), 2 is at (response)
        if pkt[ARP].psrc == "Victim_IP":  # Replace with the actual victim's IP
            victim_ip = Fore.BLUE + pkt[ARP].psrc + Style.RESET_ALL
            victim_mac = Fore.BLUE + pkt[ARP].hwsrc + Style.RESET_ALL
            attacker_ip = Fore.RED + pkt[ARP].pdst + Style.RESET_ALL
            attacker_mac = Fore.RED + pkt[ARP].hwdst + Style.RESET_ALL
        else:
            victim_ip = Fore.RED + pkt[ARP].pdst + Style.RESET_ALL
            victim_mac = Fore.RED + pkt[ARP].hwdst + Style.RESET_ALL
            attacker_ip = Fore.BLUE + pkt[ARP].psrc + Style.RESET_ALL
            attacker_mac = Fore.BLUE + pkt[ARP].hwsrc + Style.RESET_ALL

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] ARP spoof detected:")
        print(f"  Victim IP: {victim_ip}, MAC: {victim_mac}")
        print(f"  Attacker IP: {attacker_ip}, MAC: {attacker_mac}")

def start_sniffing():
    global sniffing_active
    sniffing_active = True
    print("Starting network attack detection...")
    # Sniff ARP packets to detect ARP spoofing
    sniff(filter="arp", prn=arp_spoof_detect, store=0)
    sniffing_active = False

def main():
    print("Network Attack Detection Tool - Developed by Ikramul Molla")
    print("Press 'q' or 'Q' then Enter to stop sniffing.")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

    while True:
        choice = input("Press 'q' or 'Q' then Enter to quit, or any other key to continue: ").strip().lower()
        if choice == 'q':
            print("Stopping sniffing...")
            sniffing_active = False
            break

        if not sniff_thread.is_alive() and not sniffing_active:
            print("Restarting sniffing...")
            sniff_thread = threading.Thread(target=start_sniffing)
            sniff_thread.start()

    sniff_thread.join()

if __name__ == "__main__":
    main()
