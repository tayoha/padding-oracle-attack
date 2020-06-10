# Padding Oracle Attack

The padding oracle attack is a cryptographic attack on weak implementations of AES with CBC mode encryption and the PKCS-7 padding standard. Upon submitting a multitude of ciphertexts to the oracle which encrypts and decrypts messages, the original message may be discovered based solely on the feedback given by the oracle after each ciphertext submission.

The attacker may alter the last byte of the ciphertext, knowing that at least one byte of padding is required in the original message. If the oracle responds by saying that the padding is incorrect, the attacker may revert the ciphertext back to its original form, and alter the next highest byte. The pattern continues until the attacker no longer receives an invalid padding message (and instead receives an invalid MAC message, indicating that the message given does not correspond to the Message Authentication Code given), in which case the attacker has discovered the length of the padding. Therefore, the attacker is able to discover the encryption key values associated with the last few bytes of padding and, from there, reverse the encryption to uncover the last few bytes of plaintext. From there, the attacker uses the key values to alter the ciphertext such that each padding byte is increased by 1. Then, the entire process repeats until the attacker has decrypted the whole message. The plaintext is then printed to the terminal. When the attacker has discovered the key values for an entire block of ciphertext, it throws away that block and starts on the next highest block with an intended padding value of 1.

This oracle implementation does not provide feedback distinguishing between invalid padding and an invalid MAC, but rather says "invalid" if a ciphertext contains either of those issues. Because it takes more time to check for an invalid MAC than invalid padding, this attacker implementation conducts a timing side channel attack to distinguish between the two responses. A time delay has been put in place on the oracle side to make distinguishing easier for demonstration. This delay may be adjusted according to the length of the ciphertext, the speed of the computer on which the program is running, etc.

To demonstrate the oracle and attacker as two separate entities with no access to each others' code or memory, they are two separate programs ("attack.py" and "oracle.py", respectively) which communicate only through sockets.

The input ciphertext (for the attacker to decrypt) may be changed using the "change_input.py" program. This program prompts the user to enter a message, encrypts the message according to the standards described above, and writes the encrypted message to the file "attack_input.txt". The attacker reads from this file.

## Usage

These programs were written in python3 and must be run in python3.

If you'd like to change the input message, run change_input.py using the following command:

python3 change_input.py

Start the oracle using the following command:

python3 oracle.py

Then, start the attacker using the following command:

python3 attack.py

When the attacker has decrypted the message, both programs will finish.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to be changed.