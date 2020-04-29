import os
import subprocess
import socket
import json
import datetime
import copy

BLOCK_SIZE = 16

def send_ciphertext(ciphertext_msg, sock):
    # send ciphertext to oracle
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.connect(("localhost", 8000))
    temp_sock.sendall(json.dumps(ciphertext_msg).encode('utf-8'))
    temp_sock.close()
    # receive oracle response
    try:
        oracle_sock, address = sock.accept()
    except socket.timeout:
        print("oracle did not respond")
        exit(1)
    message_chunks = []
    while True:
        try:
            data = oracle_sock.recv(4096)
        except socket.timeout:
            continue
        if not data:
            break
        message_chunks.append(data)
    oracle_sock.close()
    message_bytes = b''.join(message_chunks)
    message_str = message_bytes.decode("utf-8")
    message_dict = json.loads(message_str)
    response = message_dict["status"]
    return response

def get_status(ciphertext_test, sock):
    ciphertext_msg = {
        "ciphertext": ciphertext_test.hex()
    }
    first = datetime.datetime.now()
    response = send_ciphertext(ciphertext_msg, sock)
    second = datetime.datetime.now()
    time_elapsed = (second - first).total_seconds()
    if response == "error":
        if float(time_elapsed) > 0.02:
            # invalid mac
            return "invalid mac"
        else:
            # invalid padding
            return "invalid padding"
    else:
        # correct value
        return "valid"

def send_shutdown():
    shutdown_msg = {
        "status": "shutdown"
    }
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.connect(("localhost", 8000))
    temp_sock.sendall(json.dumps(shutdown_msg).encode('utf-8'))
    temp_sock.close()

def main():
    # set up socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("localhost", 8001))
    sock.listen(5)
    sock.settimeout(3)

    # get ciphertext
    in_file = open("attack_input.txt", "r")
    ciphertext_hex = in_file.read()
    ciphertext = bytearray.fromhex(ciphertext_hex)
    num_blocks = len(ciphertext) / BLOCK_SIZE
    in_file.close()

    # this is the byte array that we will be changing to find the right values
    ciphertext_test = copy.deepcopy(ciphertext)

    # first loop: find original number of padding bytes
    pad_num = 0
    for i in reversed(range(len(ciphertext) - BLOCK_SIZE)):
        ciphertext_test[i] = 0
        status = get_status(ciphertext_test, sock)
        ciphertext_test = copy.deepcopy(ciphertext)
        if status == "invalid padding":
            pad_num += 1
        else:
            break

    # calculate s values for original pad bytes
    s_values = [0] * (len(ciphertext) - BLOCK_SIZE)
    for i in reversed(range(len(ciphertext) - BLOCK_SIZE - pad_num, len(ciphertext) - BLOCK_SIZE)):
        s_val = ciphertext[i] ^ pad_num
        s_values[i] = s_val

    # find s value for next bit
    blocks_lost = 0
    block_last_index = len(ciphertext) - BLOCK_SIZE - 1
    index_to_alter = block_last_index - pad_num
    while True:
        if pad_num == 16:
            # reset pad_num
            pad_num = 1
            blocks_lost += 1
            if len(ciphertext) - (BLOCK_SIZE * blocks_lost) == BLOCK_SIZE:
                break
            # scrap the last block of ciphertext_test
            ciphertext_test = copy.deepcopy(ciphertext[:(-1 * BLOCK_SIZE * blocks_lost)])
            block_last_index -= BLOCK_SIZE
        else:
            # increment pad_num
            pad_num += 1
            # increment all current pad bits
            for i in reversed(range(index_to_alter + 1, block_last_index + 1)):
                ciphertext_test[i] = s_values[i] ^ (pad_num)
        # loop through all values of next bit down until padding is valid
        val = 0
        while True:
            ciphertext_test[index_to_alter] = val
            status = get_status(ciphertext_test, sock)
            if status == "invalid mac":
                s_val = val ^ (pad_num)
                s_values[index_to_alter] = s_val
                break
            val += 1
        index_to_alter -= 1
    msg = bytearray()
    for i, s_val in enumerate(s_values):
        plaintext_byte = s_val ^ ciphertext[i]
        msg.append(plaintext_byte)
    print(msg.decode("latin-1"))
    send_shutdown()

if __name__ == "__main__":
    main()