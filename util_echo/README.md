# Echo client and servers

## 0. Requirements

- TLSe dependencies (`sudo apt-get install libtomcrypt-dev libtommath-dev`)
- Homa kernel module loaded
    - Please refer to [homa-artiface](https://github.com/uoenoplab/homa-artifact) if you are on Cloudlab
    - Or simply compile [HomaModule](https://github.com/PlatformLab/HomaModule) and load it manually
- `homa_ktls` protocol
    For `homa_ktls` protocol, [`homa_ktls`](../homa_ktls/) must be loaded, please refer to [README of `homa_ktls`](../homa_ktls/README.md)

## 1. Build 

```make all```

(for deubg info printed and `gdb` support, use `make debug` instead)

## 2. Run

```
$ ./echo_client 
usage ./echo_client hostname port reqsize reqnum protocol
```

```
$ ./echo_server
usage ./echo_server port protocol
```

## Useful Notes

### Arguments

- protocols supported: `homa` `homa_ulp` `homa_ktls` `homa_tls` `tcp` `tcp_ktls` `tcp_ktls12` `tcp_tls`
- for all tcp based ones, server quits after one session, re-launch is expected
- for `homa_ktls`, `tcp_ktls` and `tcp_ktls12`, no key exchange, if you need measure key exchange time, please use `homa_tls` and `tcp_tls`

### [Benchmark](bench.py)

A [benchmark script](bench.py) is also suppied to run measurements between various message size and protocols (`homa`, `homa_ktls`, `tcp`, `tcp_ktls`)

You need to change following lines in the benchmark to set up nodes
```
ssh_username = "s2168079" # ssh username for both client-node and server-node

server_ssh_hostname = "hp115.utah.cloudlab.us" # server-node - ssh address
server_echo_ip = "10.10.1.3" # server-node - expriement nic addr

client_ssh_hostname = "hp120.utah.cloudlab.us" # client-node - ssh address
client_echo_ip = "10.10.1.2" # client-node - expriement nic addr
```
and following lines to configure payload size and protocols to test
```
reqlens = [16, 64, 512, 1024, 1380]
protos = ["homa", "homa_ktls", "tcp", "tcp_ktls", "tcp_ktls12"]
```

### [Hardcode-key](../log/echo/hardcodekey/)

To eliminate the process of handshaking, there are some hardcode keys in this program. I have kept context for those keys and packet sniffing samples to validation and reproduce at [here](../log/echo/hardcodekey/)

### [Test Results](../log/echo/README.md)
