from paramiko import RSAKey

RSAKey.generate(2048).write_private_key_file("server/server.key")
print("Host Key Created")

