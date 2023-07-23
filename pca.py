from tkinter import *
from tkinter import ttk
from tkinter.ttk import *
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import os
import csv
import time

# Capture and analyze packets based on filter protocol
def packet_capture_analysis(packets, filter_protocol, src_ip, dst_ip, src_port, dst_port):
    filtered_packets = []

    for packet in packets:
            if IP in packet:
                protocol = packet[IP].proto
                if(protocol == filter_protocol):
                    filtered_packets.append(packet)
            elif IPv6 in packet:
                protocol = packet[IPv6].nh
                if(protocol == filter_protocol):
                    filtered_packets.append(packet)

    # Calculate packet stats
    packet_sizes = [len(packet) for packet in filtered_packets]
    num_packets = len(filtered_packets)
    print(num_packets)
    total_data = sum(packet_sizes)
    avg_packet_size = total_data / num_packets if num_packets > 0 else 0

    #Update Tkinter variables to display packet statistics
    num_packets_var.set(num_packets)
    total_data_var.set(total_data)
    avg_packet_size_var.set(avg_packet_size)

    #Create histogram
    fig.clear()
    ax = fig.add_subplot(111)
    ax.hist(packet_sizes)
    ax.set_title("Packet Size Distribution")
    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("Frequency")
    canvas.draw()

    # Update the filtered packets listbox
    packet_listbox.delete(0, END)
    for packet_index, packet in enumerate(filtered_packets):
        packet_listbox.insert(packet_index, f"Packet {packet_index+1}")

    # Store filtered packets
    global filtered_packets_data
    filtered_packets_data = filtered_packets

    return filtered_packets

#To filter on basis of a keyword in payload
# def filter_by_payload_content(packets, keyword):
#     filtered_packets = []
#     for packet in packets:
#         if packet.payload and keyword.lower() in packet.payload.decode('utf-8').lower():
#             filtered_packets.append(packet)
#     return filtered_packets

#Display packet details in new window
def show_packet_details(packet):
    details_window = Toplevel(second_frame)
    details_window.title("Packet Details")
    packet_details_text = Text(details_window)
    packet_details_text.pack(expand=YES, fill=BOTH)
    packet_details_text.insert(END, packet.show(dump=True))

#All packets using Scapy's sniff function
def capture_all_packets(num_packets):
    packets = sniff(count=num_packets)
    global all_packets_data
    all_packets_data = packets
    return packets

#Display pie chart of protocol distribution
def visualize_protocol_distribution(packets):
    protocol_counts = {}
    for packet in packets:
        if IP in packet:
            protocol = packet[IP].proto
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        elif IPv6 in packet:
            protocol = packet[IPv6].nh
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    labels = []
    counts = []
    for proto in range(256):
        if proto in protocol_counts:
            labels.append(f"Protocol {proto}")
            counts.append(protocol_counts[proto])

    fig = plt.Figure(figsize=(5, 5), dpi=100)
    ax = fig.add_subplot(111)
    ax.clear()  # Clear previous plot before displaying the new one
    ax.pie(counts, labels=labels, autopct="%1.1f%%")
    ax.set_title("Protocol Distribution")

    # Create a new window to display the chart
    chart_window = Toplevel(second_frame)
    chart_window.title("Protocol Distribution Chart")
    chart_canvas = FigureCanvasTkAgg(fig, master=chart_window)
    chart_canvas.draw()
    chart_canvas.get_tk_widget().pack()

#Export packets info as csv
def export_packets_to_csv(packets, filename):
    with open(filename, "w", newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Packet Number", "Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port", "Payload Size"])
        for packet_index, packet in enumerate(packets):
            if IP in packet:
                protocol = packet[IP].proto
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
            elif IPv6 in packet:
                protocol = packet[IPv6].nh
                source_ip = packet[IPv6].src
                destination_ip = packet[IPv6].dst
            else:
                protocol = "Unknown"
                source_ip = "Unknown"
                destination_ip = "Unknown"

            source_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "Unknown")
            destination_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "Unknown")
            payload_size = len(packet.payload) if packet.payload else 0

            writer.writerow([packet_index + 1, protocol, source_ip, destination_ip, source_port, destination_port, payload_size])

#Replay captured packets with specified delay
def replay_packets(packets, replay_delay=0.1):
    for packet in packets:
        sendp(packet, verbose=0)  
        time.sleep(replay_delay)

#Handle run button
def on_run_button_click():
    num_packets = int(num_packets_entry.get())
    filter_protocol = int(filter_protocol_entry.get()) if filter_protocol_entry.get() else None
    src_ip = src_ip_entry.get()
    dst_ip = dst_ip_entry.get()
    src_port = int(src_port_entry.get()) if src_port_entry.get() else None
    dst_port = int(dst_port_entry.get()) if dst_port_entry.get() else None

    # Capture and filter packets
    packets = capture_all_packets(num_packets)
    filtered_packets = packet_capture_analysis(all_packets_data, filter_protocol, src_ip, dst_ip, src_port, dst_port)

#Handle packet selection in listbox
def on_packet_select(event):
    selected_index = packet_listbox.curselection()
    if selected_index:
        selected_packet = filtered_packets_data[int(selected_index[0])]
        show_packet_details(selected_packet)

def on_visualize_protocol_button_click():
    visualize_protocol_distribution(all_packets_data)

def on_export_data_button_click():
    export_packets_to_csv(filtered_packets_data, "captured_packets.csv")

def on_replay_button_click():
    replay_packets(filtered_packets_data)

root = Tk()
root.title("Packet Capture Analysis Tool")
root.geometry("500x400")

# Create main frame to keep all GUI elements
main_frame = Frame(root)
main_frame.pack(fill=BOTH, expand=1)

#Create a canvas to allow scrolling
my_canvas = Canvas(main_frame)
my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

# Add a scrollbar to the canvas
my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
my_scrollbar.pack(side=RIGHT, fill=Y)  
my_canvas.configure(yscrollcommand=my_scrollbar.set)

# Bind the canvas to scrollbar for scrolling
my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

# Create second frame to hold the GUI elements within the canvas
second_frame = Frame(my_canvas)
my_canvas.create_window((0,0), window=second_frame, anchor="nw")

filtered_packets_data = []
all_packets_data = []
num_packets_var = IntVar()
total_data_var = IntVar()
avg_packet_size_var = DoubleVar()

num_packets_label = Label(second_frame, text="Number of Packets:")
num_packets_entry = Entry(second_frame)
filter_protocol_label = Label(second_frame, text="Filter Protocol:")
filter_protocol_entry = Entry(second_frame)
src_ip_label = Label(second_frame, text="Source IP:")
src_ip_entry = Entry(second_frame)
dst_ip_label = Label(second_frame, text="Destination IP:")
dst_ip_entry = Entry(second_frame)
src_port_label = Label(second_frame, text="Source Port:")
src_port_entry = Entry(second_frame)
dst_port_label = Label(second_frame, text="Destination Port:")
dst_port_entry = Entry(second_frame)

num_packets_label2 = Label(second_frame, text="Number of Filtered Packets:")
num_packets_value = Label(second_frame, textvariable=num_packets_var)
total_data_label = Label(second_frame, text="Total Filtered Data Transferred:")
total_data_value = Label(second_frame, textvariable=total_data_var)
avg_packet_size_label = Label(second_frame, text="Average Filtered Packet Size:")
avg_packet_size_value = Label(second_frame, textvariable=avg_packet_size_var)

num_packets_label.grid(row=0, column=0, sticky="w")
num_packets_entry.grid(row=0, column=1, sticky="w")
filter_protocol_label.grid(row=1, column=0, sticky="w") 
filter_protocol_entry.grid(row=1, column=1, sticky="w") 
src_ip_label.grid(row=2, column=0, sticky="w") 
src_ip_entry.grid(row=2, column=1, sticky="w") 
dst_ip_label.grid(row=3, column=0, sticky="w") 
dst_ip_entry.grid(row=3, column=1, sticky="w") 
src_port_label.grid(row=4, column=0, sticky="w") 
src_port_entry.grid(row=4, column=1, sticky="w") 
dst_port_label.grid(row=5, column=0, sticky="w") 
dst_port_entry.grid(row=5, column=1, sticky="w") 

run_button = Button(second_frame, text="Run", command=on_run_button_click)
run_button.grid(row=6, column=1, columnspan=2)

num_packets_label2.grid(row=7, column=0, sticky="w") 
num_packets_value.grid(row=7, column=1, sticky="w") 
total_data_label.grid(row=8, column=0, sticky="w") 
total_data_value.grid(row=8, column=1, sticky="w") 
avg_packet_size_label.grid(row=9, column=0, sticky="w") 
avg_packet_size_value.grid(row=9, column=1, sticky="w") 

fig = plt.Figure(figsize=(5, 4), dpi=100)
canvas = FigureCanvasTkAgg(fig, master=second_frame)
plot_widget = canvas.get_tk_widget()
plot_widget.grid(row=10, columnspan=2, sticky="ew")

# Create the listbox for displaying individual packets
packet_listbox = Listbox(second_frame, selectmode=SINGLE)
packet_listbox.grid(row=11, columnspan=2, sticky="nsew")

# Add a scrollbar to the listbox
packet_scrollbar = Scrollbar(second_frame, command=packet_listbox.yview)
packet_scrollbar.grid(row=11, column=2, sticky="ns")
packet_listbox.config(yscrollcommand=packet_scrollbar.set)

packet_listbox.bind("<<ListboxSelect>>", on_packet_select)
visualize_protocol_button = Button(second_frame, text="Visualize Protocol Distribution", command=on_visualize_protocol_button_click)
visualize_protocol_button.grid(row=12, columnspan=2)

export_data_button = Button(second_frame, text="Export as CSV", command=on_export_data_button_click)
export_data_button.grid(row=13, columnspan=2)

replay_button = Button(second_frame, text="Replay Packets", command=on_replay_button_click)
replay_button.grid(row=14, columnspan=2)

root.mainloop()
