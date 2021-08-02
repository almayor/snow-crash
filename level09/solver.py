f = open('/home/user/level09/token')
tmp = f.read
res = ''
i = 0
while i < (len(tmp) - 1):
	pos = ord(tmp[i])
	res = res + chr(pos - i)
	i += 1
print(res)