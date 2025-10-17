# port scanner
import socket
import threading
from queue import Queue

target = "192.168.1.11" # port scanning my own machine
queue = Queue()
open_ports = []

def portscan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP internet socket 
        s.connect((target, port)) # True of you can connect, False if not
        return True 
    except:
        return False

def fill_queue(port_list):
    for port in port_list:
        queue.put(port)

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print(f"[+] Port {port} is open")
            open_ports.append(port)

port_list = range(1, 65535) 
fill_queue(port_list)

thread_list = []
for t in range (10):
    thread = threading.Thread(target=worker)
    thread_list.append(thread)

for thread in thread_list:
    thread.start()

for thread in thread_list:
    thread.join()

print(f"Open ports: {open_ports}")
