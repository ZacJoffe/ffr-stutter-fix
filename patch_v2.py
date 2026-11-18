import shutil
import struct
from pathlib import Path
import sys
from dataclasses import dataclass
import re

# TODO backup file
GAME_ASSEMBLY_DLL_PATH = "./GameAssembly.dll_bak"

# TODO find other signatures
# this FieldPlayer.GetMoveSpeed function disassembles to something like (snippet from objdump output):
#```
#    180f00ac0:	f3 0f 10 05 ac 09 d5 00 	movss  xmm0,DWORD PTR [rip+0xd509ac]        # 0x181c51474
#    180f00ac8:	f3 0f 5e 81 a4 00 00 00 	divss  xmm0,DWORD PTR [rcx+0xa4]
#```
# this is roughly "load 0.24 from .rdata, then divide 0.24 / entityMoveMagnification"
#
# we want to patch 0.24. this is referenced in a few other places (if we grep the disassembled code
# for 0x181c51474 we get 3 hits). 0x181c51474 is in the .rdata section and will likely change in the
# future if the game is updated.
#
# I'm assuming this code to get the player's move speed is stable and will not be changed unless the
# devs update the movement speed logic, which I think is very unlikely. however, the rip
# displacement is not stable and will probably move (alongside the VA of the constant we want to patch) if the game is updated.
# so the idea is to use the bytes from the machine code to form a unique pattern to extract the rip
# displacement. then, we can calculate the rip statically (VA of next instruction = instruction VA +
# 8), add the displacement, and get the VA of the constant we want to patch. more precisely:
#
# 1. find file offset for instruction of our pattern
# 2. rip displacement <- read bytes from file offset + 4 (signed little endian)
# 3. rip <- (file offset + 8) converted to VA
# 4. find VA of constant to patch by adding rip and rip displacement
# 5. convert VA to file offset to get target to patch
GETMOVESPEED_SIGNATURE = "f3 0f 10 05 ?? ?? ?? ?? f3 0f 5e 81 a4"
MOVESPEED_ORIGINAL_LITTLE_ENDIAN = bytes.fromhex("8fc2753e") # 0.24 in IEEE 754 little endian
MOVESPEED_PATCH_LITTLE_ENDIAN = bytes.fromhex("0ad7a33e") # 0.32 in IEEE 754 little endian


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

optional_header_offset = coff_header_offset + 20
magic_num = struct.unpack_from("<H", data, optional_header_offset)[0]
assert magic_num == 0x20b # must be a PE32+ executable and not a PE32

image_base = struct.unpack_from("<Q", data, optional_header_offset + 24)[0]

@dataclass
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    # discard rest of header values

pe_sections: list[PESection] = []

base_section_offset = coff_header_offset + 20 + optional_header_size

SECTION_TABLE_ROW_SIZE = 40

for i in range(num_sections):
    section_offset = base_section_offset + i * SECTION_TABLE_ROW_SIZE

    name = data[section_offset:section_offset + 8].rstrip(b"\0").decode("ascii")
    virtual_size = struct.unpack_from("<I", data, section_offset + 8)[0]
    virtual_address = struct.unpack_from("<I", data, section_offset + 12)[0]
    size_of_raw_data = struct.unpack_from("<I", data, section_offset + 16)[0]
    pointer_to_raw_data = struct.unpack_from("<I", data, section_offset + 20)[0]

    pe_sections.append(PESection(name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data))

def va_to_file_offset(va: int, pe_sections: list[PESection], image_base: int) -> int:
    rva = va - image_base
    for pe_section in pe_sections:
        if pe_section.virtual_address <= rva < pe_section.virtual_address + pe_section.virtual_size:
            offset_within_section = rva - pe_section.virtual_address
            if offset_within_section >= pe_section.size_of_raw_data:
                raise Exception(f"VA {va:#x} matched to {pe_section.name} but out of file bounds")

            return pe_section.pointer_to_raw_data + offset_within_section

    raise Exception(f"VA {va:#x} not found in file")

def file_offset_to_va(file_offset: int, pe_sections: list[PESection], image_base: int) -> int:
    # TODO
    raise NotImplemented


def find_pattern_file_offset(data: bytes, pattern: str) -> int:
    tokens = pattern.split()
    regex_pattern = b""
    for token in tokens:
        if token == "??":
            regex_pattern += b"."
        else:
            regex_pattern += re.escape(bytes.fromhex(token))

    compiled = re.compile(regex_pattern, re.DOTALL)
    offsets = [match.start() for match in compiled.finditer(data) ]
    if len(offsets) == 0:
        raise ValueError(f"No matches for '{pattern}'")
    elif len(offsets) > 1:
        offsets_str = ", ".join(f"{offset:#x}" for offset in offsets)
        raise ValueError(f"Found {len(offsets)} matches for '{pattern}' at offsets: {offsets_str}")

    return offsets[0]


# TODO parameterize this function
def target_file_offset(data: bytes) -> int:
    va = find_pattern_file_offset(data, GETMOVESPEED_SIGNATURE)
    file_offset = va_to_file_offset(va, pe_sections, image_base)
    rip_displacement = struct.unpack_from("<i", data, file_offset + 4)[0] # NOTE displacement operand is signed
    rip = file_offset_to_va(file_offset, pe_sections, image_base) + 8

    target_va = rip + rip_displacement
    return va_to_file_offset(target_va, pe_sections, image_base)

# TODO
fo = target_file_offset(data)


