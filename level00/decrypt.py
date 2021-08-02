def decrypt():
	ciphertext = raw_input('Please enter your encrypted sentence here:')
	shift = input('Please enter its max shift value: ')
	space = []
	z = ord('z')

	cipher_ords = [ord(x) for x in ciphertext]
	for j in range(shift):
		plaintext_ords = [
			o + j if o + j <= z else ord('a') + j - (z - o + 1) 
			for o in cipher_ords
		]
		plaintext_chars = [chr(i) for i in plaintext_ords]
		plaintext = ''.join(plaintext_chars)
		print j, ':Your encrypted sentence is:', plaintext

decrypt()