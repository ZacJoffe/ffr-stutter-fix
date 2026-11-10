import shutil
import struct
from pathlib import Path
import sys
from dataclasses import dataclass

# TODO backup file
GAME_ASSEMBLY_DLL_PATH = "./GameAssembly.dll_bak"

p = Path(GAME_ASSEMBLY_DLL_PATH)
if not p.is_file():
    print(f"Could not find file: {GAME_ASSEMBLY_DLL_PATH}")
    sys.exit(1)

with open(GAME_ASSEMBLY_DLL_PATH, "rb") as f:
    data = f.read()

# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
pe_file_offset = struct.unpack_from("<I", data, 0x3c)[0]

# ensure we are in the right place and this is a valid pe file
assert data[pe_file_offset:pe_file_offset + 4] == b"PE\x00\x00"

# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
coff_header_offset = pe_file_offset + 4
num_sections = struct.unpack_from("<H", data, coff_header_offset + 2)[0]
optional_header_size = struct.unpack_from("<H", data, coff_header_offset + 16)[0]

@dataclass
class PESection:
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    # discard rest of header values

pe_sections: dict[str, PESECTION] = {}

base_section_offset = coff_header_offset + 20 + optional_header_size

SECTION_TABLE_ROW_SIZE = 40

for i in range(num_sections):
    section_offset = base_section_offset + i * SECTION_TABLE_ROW_SIZE
    print(section_offset)
    name = data[section_offset:section_offset + 8].rstrip(b"\0").decode("ascii")
    virtual_size = struct.unpack_from("<I", data, section_offset + 8)[0]
    virtual_address = struct.unpack_from("<I", data, section_offset + 12)[0]
    size_of_raw_data = struct.unpack_from("<I", data, section_offset + 16)[0]
    pointer_to_raw_data = struct.unpack_from("<I", data, section_offset + 20)[0]

    pe_sections[name] = PESection(virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data)
