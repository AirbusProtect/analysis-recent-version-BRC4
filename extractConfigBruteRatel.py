import re
import sys
import struct
import time
from ctypes import *
from arc4 import ARC4


WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
SIZE_T = c_size_t
LPVOID = c_void_p
PVOID = LPVOID
LPCWSTR = c_wchar_p
LPCVOID = c_void_p
BOOL = c_long
LPCSTR = c_char_p
LPSTR = c_char_p

MEM_COMMIT = 0x00001000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04


class STARTUPINFO(Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress', PVOID),
        ('AllocationBase', PVOID),
        ('AllocationProtect', DWORD),
        ('PartitionId', WORD),
        ('RegionSize', SIZE_T),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD),
    ]


class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', DWORD),
        ('lpSecurityDescriptor', LPVOID),
        ('bInheritHandle', BOOL),
    ]


LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)
LPSTARTUPINFO = POINTER(STARTUPINFO)
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)
LPSIZE_T = POINTER(SIZE_T)

kernel32 = windll.kernel32
CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = [
    LPCWSTR,
    LPSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    BOOL,
    DWORD,
    LPVOID,
    LPCSTR,
    LPSTARTUPINFO,
    LPPROCESS_INFORMATION,
]
CreateProcessA.restype = BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
VirtualQueryEx.restype = SIZE_T

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, LPSIZE_T]
ReadProcessMemory.restype = BOOL



def extractConfigBRC4(dump):
    contenu_octets = dump

    def hexFormat(hexData):
        hexList = []
        for hexValue in hexData:
            if hexValue == '0x0':
                hexList.append('00')
            else:
                hexList.append(hexValue[2:].zfill(2).upper())
        return ' '.join(hexList)

    def searchKey(regex_sequence):
        contenu_hex = contenu_octets.hex()
        matchTest = re.search(regex_sequence, contenu_hex)
        if matchTest:
            matches = re.finditer(regex_sequence, contenu_hex)
            for match in matches:
                contenu_match = contenu_octets[match.start() // 2 : match.end() // 2]
                try:
                    print(f'[+] Key Str\t-> {(contenu_match[15:])[1:9].decode()}')
                except UnicodeDecodeError:
                    print(f'[+] Key Str\t-> {(contenu_match[15:])[1:9]}')
                print(f'[+] Key Hex\t-> {hexFormat([hex(i) for i in (contenu_match[15:])[1:9]])}')
                break
        else:
            return False

        return ''.join(hexFormat([hex(i) for i in (contenu_match[15:])[1:9]]))

    def searchConfig(regex_sequence):
        contenu_hex = contenu_octets.hex()
        matchTest = re.search(regex_sequence, contenu_hex)
        if matchTest:
            startIndex = matchTest.end()
            configSize = struct.unpack(
                '<I', bytes.fromhex(contenu_hex[startIndex : startIndex + 8])
            )[0]
            print(f'[+] Config Size\t-> {configSize}')
            print(f'[+] Config Hex\t-> {hexFormat( [hex(i) for i in contenu_octets[int(startIndex / 2) + 20 : int(startIndex / 2) + 20 + configSize ]])}')
            return ''.join(
                hexFormat(
                    [
                        hex(i)
                        for i in contenu_octets[
                            int(startIndex / 2)
                            + 20 : int(startIndex / 2)
                            + 20
                            + configSize
                        ]
                    ]
                )
            )

        else:
            return False

    regex_sequences_forKey = [
        r'(00){16}([1-9A-Fa-f]{1}[0-9A-Fa-f]{1}){8}([0-9A-Fa-f]{2}){8}(00){8}(..0001......)(00..)',
        r'(00){16}([1-9A-Fa-f]{1}[0-9A-Fa-f]{1}){8}([0-9A-Fa-f]{2}){8}(00){8}([0-9A-Fa-f]{2}){6}(0001)',
        r'(00){16}([1-9A-Fa-f]{1}[0-9A-Fa-f]{1}){8}([0-9A-Fa-f]{2}){8}(00){8}([0-9A-Fa-f]{2}){6}(0010)'
        
    ]
    regex_sequences_forConfig = r'(4883e4f04831c0505468)'
    for i, sequence in enumerate(regex_sequences_forKey):
        print(f'[*] Key extraction attempt {(i + 1)} of 4')
        sKey = searchKey(sequence)
        if sKey != False:
            break
    else:
        print('[-] No Key found')

    print('[*] Config extraction attempt')
    sConfig = searchConfig(regex_sequences_forConfig)
    if sConfig == False:
        print('[-] No Config Found')
    else:
        arc4 = ARC4(bytes.fromhex(sKey))
        ciphertext = bytes.fromhex(sConfig)
        config = arc4.decrypt(ciphertext)
        try:
            print(f'[+] Config txt\t-> {config.decode()}')
        except UnicodeDecodeError:
            print(f'[+] Config txt\t-> {config}')


def workerMemoryCheck(handle, file):
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    dump = b''
    while True:
        res = VirtualQueryEx(handle, address, byref(mbi), sizeof(mbi))
        if res == 0:
            break
        else:
            if mbi.State == MEM_COMMIT and (
                mbi.Protect == PAGE_READWRITE or mbi.Protect == PAGE_READONLY
            ):
                buffer = create_string_buffer(mbi.RegionSize)
                bytesRead = SIZE_T()
                if ReadProcessMemory(
                    handle, mbi.BaseAddress, buffer, mbi.RegionSize, byref(bytesRead)
                ):
                    dump += buffer.raw
                    file.write(buffer.raw)

                else:
                    print(get_last_error())

            address += mbi.RegionSize

    return dump


def dynamicDumpBRC4(cmdline):
    startupinfo = STARTUPINFO()
    startupinfo.cb = sizeof(startupinfo)
    process_information = PROCESS_INFORMATION()
    bigDump = b''

    if not CreateProcessA(
        None,
        cmdline.encode(),
        None,
        None,
        False,
        0,
        None,
        None,
        byref(startupinfo),
        byref(process_information),
    ):
        print(f'[!] Impossible to execute this program : {cmdline} !')
        sys.exit(-1)

    else:
        print(f'[*] Program launched  : {cmdline}')
        print(f'[*] Handle of program : 0x{process_information.hProcess}')
        file = open('dump.bin', 'ab')
        print('[*] Loading data into this file : dump.bin')
        for i in range(5):
            print(f'[*] Loading data step {(i + 1)} of 5')
            dump = workerMemoryCheck(process_information.hProcess, file)
            bigDump += dump
            time.sleep(0.200)

        file.close()
        print('[*] Dump file is complete.')
        print('[*] Configuration extraction is running...')
        extractConfigBRC4(bigDump)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'[!] {sys.argv[0]} [brc4 sample]')
        sys.exit(0)

    file = sys.argv[1]
    dynamicDumpBRC4(file)
