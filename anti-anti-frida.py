#!/usr/bin/env python
import lief
import sys
import random
import string
import os
if __name__ == "__main__":
    input_file = sys.argv[1]
    print(f"[*] Patch frida-agent: {input_file}")
    random_name = "".join(random.sample(string.ascii_uppercase+string.ascii_lowercase, 5))
    print(f"[*] Patch `frida` to `{random_name}``")
    binary = lief.parse(input_file)
    if not binary:
        exit()
    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"
        if "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", random_name)
        if "FRIDA" in symbol.name:
            symbol.name = symbol.name.replace("FRIDA", random_name)

    [
        (
            print(f"section={section.name} offset={hex(section.file_offset + addr)} {patch_str} -> {''.join(list(patch_str)[::-1])}"),
            binary.patch_address(section.file_offset + addr, [ord(n) for n in list(patch_str)[::-1]])  # not sure if reversing a string can be considered sufficient
        ) for section in binary.sections if section.name == ".rodata"
        for patch_str in ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]  # 字符串特征修改 尽量与源字符一样
        for addr in section.search_all(patch_str)  # Patch 内存字符串
    ]

    binary.write("done")

    for i in ["gum-js-loop", "gmain", "gdbus"]:  # comprehension with walrus notation? needs py3.8, tho
        random_name = "".join(random.sample(string.ascii_lowercase+string.ascii_uppercase, len(i)))
        print(f"[*] Patch `{i}` to `{random_name}`")
        os.system(f"sed -b -i s/{i}/{random_name}/g {input_file}")
