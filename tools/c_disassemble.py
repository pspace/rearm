import r2pipe
import argparse
import base64

def func_to_md_code(r2_pdfj):
    name = r2_pdfj["name"]
    ops = r2_pdfj["ops"]
    lines = []
    lines.append("#### " + name)
    lines.append("``` nasm")
    for op in ops:
        comment = b""
        if "comment" in op.keys():
            comment = base64.b64decode(op["comment"])

        line = op["disasm"]
        if  not op["opcode"] == op["disasm"]:
            line = line + "\t\t;" + op["opcode"]
        line = line + "\t\t" + comment.decode("utf-8")
        lines.append(line)

    lines.append("```")

    return lines


def disas_file(path, fun_names):
    r2 = r2pipe.open(path)
    r2.cmd("aaa")
    functions = r2.cmdj("afljb")

    for f in functions:
        name = f["name"]
        if ".imp." in name:
            continue
        
        valid = False
        for f in fun_names:
            if f in name:
                valid = True 
                continue
        if not valid:
            continue

        r2.cmd("s " + name)
        d = r2.cmdj("pdfj")

        fs = func_to_md_code(d)
        output_path = path + "_asm_" + name + ".markdown"
        with open(output_path, 'w') as out:
            out.write("\n".join(fs))

def get_fun_names(paths):
    names = []
    for p in paths:
        with open(p,'r') as f:
            names.extend([l.strip() for l in f])
    return names

if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser(description='Disassemble all functions with radare2')
    parser.add_argument('binary', metavar='BINARY', type=str, nargs=1,
                        help='path to input binary')
    parser.add_argument('functions', metavar='FUNCTIONNAMES', type=str, nargs=1,
                        help='functions to disassemble')


    args = parser.parse_args()
    fun_names = get_fun_names(args.functions)
    disas_file(args.binary[0], fun_names)


