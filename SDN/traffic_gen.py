from scapy.all import *
import sys

# Target configuration
if len(sys.argv) > 1:
    TARGET_IP = sys.argv[1]
else:
    print("Usage: sudo python3 traffic_gen.py <VICTIM_IP>")
    sys.exit(1)

def send_burst(name, dport, proto='tcp', display_count=1000):
    print(f"[*] Triggering {name} Alert (Sending 1 trigger packet)...")
    if proto == 'tcp':
        pkt = IP(dst=TARGET_IP)/TCP(dport=dport, flags="S")
    else:
        pkt = IP(dst=TARGET_IP)/UDP(dport=dport)/Raw(load="DEMO_TRIGGER")
    
    send(pkt, count=1, verbose=False)
    print(f"[+] Done. The NIDS should now show an attack with {display_count} packets.")

def print_menu():
    print("\n=== NIDS DEMO TRIGGER ===")
    print(f"Target: {TARGET_IP}")
    print("1. Normal Traffic (TCP/80)")
    print("2. DoS Attack (UDP/80)")
    print("3. Reconnaissance (TCP/1)")
    print("4. Malware (TCP/4444)")
    print("0. Exit")
    print("=========================")

if __name__ == "__main__":
    while True:
        print_menu()
        choice = input("Select: ")
        if choice == '1': send_burst("Normal", 80, 'tcp', 20)
        elif choice == '2': send_burst("DoS", 80, 'udp', 1000)
        elif choice == '3': send_burst("Recon", 1, 'tcp', 100)
        elif choice == '4': send_burst("Malware", 4444, 'tcp', 50)
        elif choice == '0': sys.exit()
        else: print("Invalid choice.")
