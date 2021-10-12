from ctypes import wintypes as wt
import ctypes as ct
import win32process
import win32ui
import win32api
import win32gui
import re
import argparse
import sys


class MemoryReader:
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PAGE_READWRITE = 0x0004
    WM_SYSCOMMAND = 0x0112
    WM_ACTIVATE = 0x6
    WM_HOTKEY = 0x0312
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_TERMINATE = 0x0001

    class MemoryReadError(RuntimeError):
        pass

    def __init__(self, window_name, module_name=None, hwnd=None):
        self.handle = None
        self.window_name = window_name
        self.module_name = module_name if module_name else window_name + '.exe'
        self.hwnd = hwnd
        if not hwnd:
            self.hwnd = win32ui.FindWindow(None, self.window_name).GetSafeHwnd()
        self.pid = win32process.GetWindowThreadProcessId(self.hwnd)[1]
        self.handle = self._get_handle()

    @classmethod
    def from_window(cls, hwnd, module_name=None):
        return cls(win32gui.GetWindowText(hwnd), module_name=module_name, hwnd=hwnd)

    def _get_handle(self):
        handle = ct.windll.kernel32.OpenProcess(ct.c_uint(MemoryReader.PROCESS_QUERY_INFORMATION |
                                                          MemoryReader.PROCESS_VM_READ | MemoryReader.PROCESS_VM_WRITE |
                                                          MemoryReader.PROCESS_VM_OPERATION),
                                                ct.c_int(0), ct.c_uint(self.pid))
        if handle == ct.c_void_p(0):
            raise RuntimeError('Unable to get process handle.')
        return handle

    def __del__(self):
        if self.handle:
            ct.windll.kernel32.CloseHandle(self.handle)

    def read(self, address, bytes_to_read):
        def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpBytesRead):
            _ReadProcessMemory = ct.windll.kernel32.ReadProcessMemory
            _ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ct.c_size_t, ct.c_void_p]
            _ReadProcessMemory.restype = wt.BOOL

            return _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpBytesRead)

        address = ct.c_void_p(address)
        btr = ct.c_size_t(bytes_to_read)
        buffer = ct.create_string_buffer(bytes_to_read)
        if not ReadProcessMemory(self.handle, address, ct.byref(buffer), btr, ct.c_void_p(0)):
            raise MemoryReader.MemoryReadError(f'Error reading memory. {win32api.GetLastError()}')
        return bytearray(buffer)

    def write(self, address, buffer):
        to_write = ct.create_string_buffer(buffer, len(buffer))
        address = ct.c_void_p(address)
        bytes_written = ct.c_int()
        ct.windll.kernel32.WriteProcessMemory(self.handle, address, to_write, ct.sizeof(to_write), ct.byref(bytes_written))
        return bytes_written.value

    def get_memory_regions(self):
        class MemoryBasicInformation(ct.Structure):
            _fields_ = [('base_address', ct.c_size_t), ('allocation_base', ct.c_void_p), ('allocation_protect', wt.DWORD),
                        ('partition_id', wt.WORD), ('size', ct.c_size_t), ('state', wt.DWORD),
                        ('protect', wt.DWORD), ('type', wt.DWORD)]
        PMEMORYBASICINFORMATION = ct.POINTER(MemoryBasicInformation)
        ct.windll.kernel32.VirtualProtectEx.argtypes = [wt.HANDLE, wt.LPCVOID, PMEMORYBASICINFORMATION, ct.c_size_t]
        ct.windll.kernel32.VirtualProtectEx.restype = ct.c_size_t

        addr = ct.c_size_t(0)
        regions = []
        mem_info = MemoryBasicInformation()
        while addr.value < 0x7fffffffffff:
            written = ct.windll.kernel32.VirtualQueryEx(self.handle, addr, ct.byref(mem_info), ct.sizeof(mem_info))
            if written == 0:
                break
            regions.append((mem_info.base_address or 0, mem_info.size))
            addr = ct.c_size_t(addr.value + mem_info.size)
        return regions


def get_filters(loot_filter_file):
    try:
        with open(loot_filter_file) as inp:
            filters = inp.read().split('\n')
    except FileNotFoundError as e:
        print(e)
        return None

    filters = [x.split(':') for x in filters if x and x[0] != '#']
    for x in filters:
        x[0] = re.sub(r'{([Ss]\d*)}', r'(?P<\1>.+)', x[0])
        x[0] = re.compile(x[0])
        x[1] = x[1].replace('\\n', '\n')

    return filters


def main(loot_filter_file):
    max_chunk_size = 1024 * 1024 * 128
    start_search = 'CHAT HELP\x00CHAT COMMANDS\x00To select'.encode('utf-16-le')
    end_search = 'You may not invite a player to that channel'.encode('utf-16-le')

    filters = get_filters(loot_filter_file)
    if not filters:
        print('No filters loaded.')
        sys.exit(1)

    try:
        mr = MemoryReader('Diablo II: Resurrected', 'D2R.exe')
    except win32ui.error as e:
        print(e)
        sys.exit(1)
    memory_regions = mr.get_memory_regions()

    print('Searching for string tables.')
    for base_addr, size in memory_regions:
        if size > max_chunk_size:
            continue
        try:
            mem = mr.read(base_addr, size)
        except MemoryReader.MemoryReadError:
            continue
        start_ind = 0
        while start_ind != -1:
            ind = mem.find(start_search, start_ind)
            if ind != -1:
                start_addr = base_addr + ind
                ind = mem.find(end_search, ind + 1)
                if ind != -1:
                    end_addr = base_addr + ind + len(end_search)
                    print(f'Table found at 0x{start_addr:016x} - 0x{end_addr:016x}')

                    string_table = mr.read(start_addr, end_addr - start_addr)
                    string_table = string_table.split(b'\x00\x00\x00')
                    table = []
                    for i, x in enumerate(string_table):
                        try:
                            table.append((x+b'\x00').decode('utf-16'))
                        except UnicodeDecodeError:
                            table.append(x+b'\x00')

                    for i, string in enumerate(table):
                        if type(string) in (bytes, bytearray):
                            continue

                        for filter, rep in filters:
                            match = filter.fullmatch(string)
                            if match:
                                groups = match.groupdict()
                                if len(groups) > 0:
                                    for k, v in groups.items():
                                        rep = re.sub(f'{{{k}}}', v, rep)
                                if len(rep) <= len(string):
                                    print(f'\t{i}: {string} -> {rep}')
                                    table[i] = rep.ljust(len(string), '\x00').encode('utf-16-le')
                                    break

                    for i, string in enumerate(table):
                        if type(string) is str:
                            table[i] = string.encode('utf-16-le')

                    to_write = b'\x00\x00'.join(table)[:-1]
                    mr.write(start_addr, to_write)
            start_ind = ind


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LootFilter')
    parser.add_argument('file', type=str, nargs='?', help='Loot Filter File', default='endgame_items.txt')
    args = parser.parse_args()
    main(args.file)
