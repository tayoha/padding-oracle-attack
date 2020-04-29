import hashlib
from oracle import macThenEncrypt

enc_password = "mypwdiscool"
enc_key = hashlib.sha256(enc_password.encode('utf-8')).digest()
mac_password = "newmacpwdlol"
mac_key = hashlib.sha256(mac_password.encode('utf-8')).digest()

msg = input("Please enter the message:\n").rstrip()
s = macThenEncrypt(msg.encode("utf-8"), enc_key, mac_key)
out_file = open("attack_input.txt", "w")
out_file.write(s.hex())
out_file.close()