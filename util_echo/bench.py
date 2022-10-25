import itertools
import re
import pandas as pd
from paramiko import SSHClient
from paramiko import MissingHostKeyPolicy

ssh_username = "s2168079" # ssh username for both client-node and server-node

server_ssh_hostname = "hp115.utah.cloudlab.us" # server-node - ssh address
server_echo_ip = "10.10.1.3" # server-node - expriement nic addr

client_ssh_hostname = "hp120.utah.cloudlab.us" # client-node - ssh address
client_echo_ip = "10.10.1.2" # client-node - expriement nic addr

reqlens = [16, 64, 512, 1024, 1380]
protos = ["homa", "homa_ktls", "tcp", "tcp_ktls", "tcp_ktls12"]

exps = list(itertools.product(reqlens, protos))

# server-node
echo_server_start_cmds = ["cd ~/homaTLS/echo; ./echo_server 2000 {}".format(exp[1]) for exp in exps]
echo_server_end_cmds = ["pkill echo_server" for exp in exps]

# client-node
echo_client_cmds = ["cd ~/homaTLS/echo; ./echo_client {} 2000 {} 1000000 {}".format(server_echo_ip, exp[0], exp[1]) for exp in exps]

server = SSHClient()
server.load_system_host_keys()
server.set_missing_host_key_policy(MissingHostKeyPolicy())
server.connect(server_ssh_hostname, username=ssh_username)

client = SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(MissingHostKeyPolicy())
client.connect(client_ssh_hostname, username=ssh_username)

avg_rtts = []

for i in range(len(exps)):
    print("start {} exp".format(exps[i]))

    print("send \"{}\" command to server".format(echo_server_start_cmds[i]))
    server.exec_command(echo_server_start_cmds[i])

    print("send \"{}\" command to client".format(echo_client_cmds[i]))
    client_stdin, client_stdout, client_stderr = client.exec_command(echo_client_cmds[i])
    
    lines = client_stdout.readlines()
    print(lines)
    avg_rtt = float(re.findall(r"[-+]?(?:\d*\.\d+|\d+)", lines[1])[0])
    avg_rtts.append(avg_rtt)

    print("send \"{}\" command to server".format(echo_server_end_cmds[i]))
    server.exec_command(echo_server_end_cmds[i])

    print("finish {} exp - avg_rtt {}".format(exps[i], avg_rtt))

exps_data = [(exps[i][0], exps[i][1], avg_rtts[i]) for i in range(len(exps))]
df = pd.DataFrame(exps_data, columns=['reqlen', 'protocol', "avg_rtt"])
df.to_csv("bench.csv")
