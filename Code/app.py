import tkinter as tk
from tkinter import messagebox
from Packet_build import Packet




# Tkinter GUI Application
def send_packet_gui():
    mac = mac_entry.get()
    ip_src = ip_src_entry.get()
    ip_dst = ip_dst_entry.get()
    sport = int(sport_entry.get())
    dport = int(dport_entry.get())
    payload = payload_entry.get()

    pkt = Packet(mac)
    pkt.add_ip_layer(ip_src, ip_dst)
    pkt.add_tcp_layer(sport, dport)
    pkt.add_raw_payload(payload)
    pkt.send_packet()
    messagebox.showinfo("Success", "Packet Sent!")

# GUI Setup
root = tk.Tk()
root.title("Packet Sender")
root.geometry("400x300")

tk.Label(root, text="MAC Address:").pack()
mac_entry = tk.Entry(root, width=40)
mac_entry.pack()

tk.Label(root, text="Source IP:").pack()
ip_src_entry = tk.Entry(root, width=40)
ip_src_entry.pack()

tk.Label(root, text="Destination IP:").pack()
ip_dst_entry = tk.Entry(root, width=40)
ip_dst_entry.pack()

tk.Label(root, text="Source Port:").pack()
sport_entry = tk.Entry(root, width=40)
sport_entry.pack()

tk.Label(root, text="Destination Port:").pack()
dport_entry = tk.Entry(root, width=40)
dport_entry.pack()

tk.Label(root, text="Payload:").pack()
payload_entry = tk.Entry(root, width=40)
payload_entry.pack()

tk.Button(root, text="Send Packet", command=send_packet_gui).pack()

root.mainloop()


"aa:bb:cc:dd:ee:ff"