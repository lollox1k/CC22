from pwn import *


r = remote('cyberchallenge.diag.uniroma1.it', 5002)
data = []
for _ in range(10):
    line = r.recvline().decode().strip()
    #print(line)
    data.append( bin(int(line))[2:] )

data_int = []
for d in data:
    arr = []
    for c in d:
        arr.append(int(c))
    data_int.append(arr)

#add padding 0's in front
for i in range(len(data_int)):
    if len(data_int[i]) < 96:
        data_int[i] = [0]*(96-len(data_int[i])) + data_int[i]


#print(data_int)

#first pick or or and based on 1's frequency

ors = []
ands = []

for d in data_int:
    counter = 0
    for s in d:
        if s == 1:
            counter += 1
    if counter/96 >= 0.5:
        ors.append(d)
    else:
        ands.append(d)

'''
print('ands')
print(ands)
print('\n ors')
print(ors)
'''
#pick most probable bits for plaintext


#majority vote for certain bits: if and is 1 then bit is 1, if or is 0 then bit is 0
#
# 0  0 | 0     0  0 | 0
# 1  0 | 1     1  0 | 0
# 0  1 | 1     0  1 | 0
# 1  1 | 1     1  1 | 1
#
plain = ''

for i in range(96):
    #look inside ors
    zeros_or = 0
    ones_or = 0
    for o in ors:
        if o[i] == 0:
            zeros_or += 1
        else:
            ones_or += 1
    zeros_and = 0
    ones_and = 0
    for a in ands:
        if a[i] == 0:
            zeros_and += 1
        else:
            ones_and += 1
    #normalize
    zeros_or /= len(ors)
    ones_or /= len(ors)

    zeros_and /= len(ands)
    ones_and /= len(ands)

    #now we know zeros and ones in
    if ones_or == 1:
        plain += '1'
    elif zeros_and == 1:
        plain += '0'
    '''
    elif zeros_and == 0 and ones_or > 0.3*len(ors):
        plain += '0'
    elif ones_and > 0.3*len(ands) and ones_or == len(ors):
        plain += '1'
    else:
        plain += '0'
    '''

print(len(plain))
print(plain)
print(int(plain,2))

r.interactive()

r.send( str(int(plain)).encode())
