import lief
import os

currentDIR = os.path.dirname(__file__)

target = os.path.join(currentDIR, "..", "prebuilt", "arm64-v8a", "libuinjector.so")

lf : lief.ELF.Binary = lief.parse(target)

lf.remove_library("libart.so")

lf.write(os.path.join(currentDIR , "libuinjector.so"))

print(lf.header)