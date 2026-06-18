import socket
import syslog
import subprocess

def log_warning(ip):
    message = "WARNING: Malicious activity detected from {}".format(ip)
    syslog.syslog(syslog.LOG_WARNING, message)

def block_ip(ip):
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def handle_connection(conn, addr):
    log_warning(addr[0])
    block_ip(addr[0])
    conn.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 1000))
s.listen(1)

while True:
    conn, addr = s.accept()
    handle_connection(conn, addr)