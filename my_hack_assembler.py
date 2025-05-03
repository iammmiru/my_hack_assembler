import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional

_COMP = {
    "0": "101010",
    "1": "111111",
    "-1": "111010",
    "D": "001100",
    "A": "110000",
    "!D": "001101",
    "!A": "110001",
    "-D": "001111",
    "-A": "110011",
    "D+1": "011111",
    "A+1": "110111",
    "D-1": "001110",
    "A-1": "110010",
    "D+A": "000010",
    "D-A": "010011",
    "A-D": "000111",
    "D&A": "000000",
    "D|A": "010101",
}
_DEST = {
    None: "000",
    "M": "001",
    "D": "010",
    "MD": "011",
    "A": "100",
    "AM": "101",
    "AD": "110",
    "AMD": "111",
}
_JUMP = {
    None: "000",
    "JGT": "001",
    "JEQ": "010",
    "JGE": "011",
    "JLT": "100",
    "JNE": "101",
    "JLE": "110",
    "JMP": "111",
}


class HackAssemblyError(Exception):
    pass


class HackAssembler:
    """
    Translate Hack Assembly instructions to Hack binary instructions
    """

    def __init__(self, input_file: Path):
        self._input_file = input_file

        self._symbol_table = self.init_symbol_table()

        self._effective_line_number = 0
        self._symbol_count = 0

    @staticmethod
    def init_symbol_table() -> Dict:
        sym_table = {}
        for i in range(16):
            sym_table[f"R{i}"] = i
        sym_table["SCREEN"] = 16384
        sym_table["KBD"] = 24576
        sym_table["SP"] = 0
        sym_table["LCL"] = 1
        sym_table["ARG"] = 2
        sym_table["THIS"] = 3
        sym_table["THAT"] = 4
        return sym_table

    def strip_down(self, line: str, line_number: int) -> str:
        """
        Removes all white spaces and comments from the input line.

        Comments start with "//". Raises AssemblyError on stray '/'.
        """
        stripped = "".join(line.split())
        for i, ch in enumerate(stripped):
            if ch == "/":
                if i + 1 < len(stripped) and stripped[i + 1] == "/":
                    if i == 0:
                        return ""
                    else:
                        return stripped[:i]
                else:
                    raise HackAssemblyError(
                        f"Invalid '/' at line {self._input_file}:{line_number}"
                    )
            else:
                continue
        return stripped

    def first_pass(self, instruction: str, line_number: int):
        """
        Part of the first pass iteration.

        Reads all Labels which is wrapped around parenthesis, and add to the symbol table.
        Raises AssemblyError if a label is defined multiple times, or on stray "("
        """
        if instruction == "":
            return ""
        if instruction[0] == "(":
            if instruction[-1] == ")":
                label = instruction[1:-1]
                if label not in self._symbol_table:
                    self._symbol_table[label] = self._effective_line_number
                    return ""
                else:
                    raise HackAssemblyError(
                        f"The variable {label} at {self._input_file}:{line_number} is already defined"
                    )
            else:
                raise HackAssemblyError(
                    f"Missing closing ')': {self._input_file}:{line_number}"
                )
        else:
            self._effective_line_number += 1
            return instruction

    def process_instruction(self, instruction, line_number) -> Optional[str]:
        if instruction == "":
            return None
        if instruction[0] == "@":
            return self.process_a_instruction(instruction, line_number)
        else:
            return self.process_c_instruction(instruction, line_number)

    def process_a_instruction(self, instruction: str, line_number: int) -> str:
        """
        An instruction starts with "@" is an A instruction

        May raise AssemblyError
        """
        if len(instruction) <= 1:
            raise HackAssemblyError(
                f"Missing address for A instruction at {self._input_file}:{line_number}"
            )
        try:
            address_decimal = int(instruction[1:])
        except ValueError:
            address_symbol = instruction[1:]
            if address_symbol not in self._symbol_table:
                self._symbol_table[address_symbol] = 16 + self._symbol_count
                self._symbol_count += 1
            address_decimal = self._symbol_table.get(address_symbol)
        address_binary = format(address_decimal, "015b")
        return "0" + address_binary

    def process_c_instruction(self, instruction: str, line_number: int) -> str:
        """
        An instruction does not starts with "@" is a C instruction

        May raise AssemblyError
        """
        if "=" in instruction:
            dest_inst, rest = instruction.split("=", 1)
        else:
            dest_inst, rest = None, instruction

        if ";" in instruction:
            comp_inst, jump_inst = rest.split(";", 1)
        else:
            comp_inst, jump_inst = rest, None

        try:
            a_bit = "1" if "M" in comp_inst else "0"
            comp_inst = comp_inst.replace("M", "A")
            comp_bits = _COMP[comp_inst]
            dest_bits = _DEST[dest_inst]
            jump_bits = _JUMP[jump_inst]
        except KeyError:
            raise HackAssemblyError(
                f"Illegal C-instruction '{instruction}' at {self._input_file}:{line_number}"
            )

        return "111" + a_bit + comp_bits + dest_bits + jump_bits


def parse_input() -> Tuple[Path, Path]:
    parser = argparse.ArgumentParser()

    parser.add_argument("input_file", type=Path, help="Path to the assembly code")
    parser.add_argument(
        "output_path", type=Path, nargs="?", help="Output file or directory"
    )
    args = parser.parse_args()

    input_path: Path = args.input_file.resolve()
    input_file_name = input_path.stem  # e.g. "Prog" from "Prog.asm"

    if args.output_path is None:
        # No output specified → same directory, same stem
        output_path = input_path.with_name(f"{input_file_name}.hack")
    else:
        out: Path = args.output_path
        if out.is_dir():
            # User gave a directory → place <stem>.hack inside it
            output_path = (out / f"{input_file_name}.hack").resolve()
        else:
            # User gave a file (or file-like) → enforce .hack extension
            if out.suffix != ".hack":
                raise RuntimeError("Output extension must be .hack")
            output_path = out.resolve()

    return input_path, output_path


def process_assembly(input_file: Path) -> List[str]:
    assembler = HackAssembler(input_file)

    effective_instructions: List[str] = []
    with open(input_file, "r", encoding="utf-8") as f:
        for n, line in enumerate(f):
            line_number = n + 1
            pure_inst = assembler.strip_down(line, line_number)
            effective_instructions.append(assembler.first_pass(pure_inst, line_number))

    result = []
    for n, inst in enumerate(effective_instructions):
        line_number = n + 1
        if inst:
            result.append(assembler.process_instruction(inst, line_number))
    return result


def main():
    try:
        input_file, output_file = parse_input()
        binary_instructions = process_assembly(input_file)

        with open(output_file, "w", encoding="utf-8") as f:
            f.writelines(line + "\n" for line in binary_instructions)
    except HackAssemblyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
