import shutil

WALK_SPEED_NEEDLE = b"\x8f\xc2\x75\x3e" # little endian representation of 0.24
WALK_SPEED_FIXED = b"\x3e\xa3\xd7\x0a"  # little endian representation of 0.32

shutil.copy("./private/GameAssembly.dll", "./private/GameAssembly.dll_bak")

# TODO smarter dll finding
with open("./private/GameAssembly.dll", "rb") as f:
    data = f.read()

assert data.count(WALK_SPEED_NEEDLE) == 1

data = data.replace(WALK_SPEED_NEEDLE, WALK_SPEED_FIXED)

with open("./private/GameAssembly.dll", "wb") as f:
    f.write(data)


