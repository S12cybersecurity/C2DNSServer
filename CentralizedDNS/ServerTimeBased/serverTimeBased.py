import socket
import base64
from dnslib import DNSRecord, RR, A
import time
from datetime import datetime

IP = "0.0.0.0"
PORT = 533

def is_business_hours():
    now = datetime.now().time()
    return (9 <= now.hour < 23)  # 9AM-5PM

def handle_request(data, addr, sock):
    try:
        dns_record = DNSRecord.parse(data)
        qname = str(dns_record.q.qname)
        encoded_cmd = qname.split('.')[0]

        # Decode command
        try:
            decoded_cmd = base64.b64decode(encoded_cmd).decode('utf-8')
        except:
            decoded_cmd = encoded_cmd

        print(f"[+] Received: {decoded_cmd} from {addr[0]}")

        # Simulate command execution
        response = f"Executed: {decoded_cmd} at {time.ctime()}"
        encoded_resp = base64.b64encode(response.encode()).decode('utf-8')

        # Send response as fake DNS answers
        reply = dns_record.reply()
        reply.add_answer(RR(qname, rdata=A("127.0.0.1")))  # Dummy IP
        sock.sendto(reply.pack(), addr)

    except Exception as e:
        print(f"[-] Error: {e}")

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print(f"[*] Listening on {IP}:{PORT}")

    while True:
        if is_business_hours():  # Only respond during business hours
            data, addr = sock.recvfrom(512)
            handle_request(data, addr, sock)
        else:
            time.sleep(60)  # Sleep if outside operational window

if __name__ == "__main__":
    start_server()