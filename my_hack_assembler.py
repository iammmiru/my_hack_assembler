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
        """
        Initializes the Assembler object.

        Args:
            input_file: The path to the assembly input file.
        """
        self._input_file = input_file

        self._symbol_table = self.init_symbol_table()

        self._effective_line_number = 0
        self._symbol_count = 0

    @staticmethod
    def init_symbol_table() -> Dict:
        """
        Initializes and returns the predefined symbol table for the Hack assembly language.

        This table contains mappings for:
        - Registers (R0 to R15)
        - Memory segments (SP, LCL, ARG, THIS, THAT)
        - I/O addresses (SCREEN, KBD)

        Returns:
            Dict: A dictionary representing the symbol table with predefined symbols and their addresses.
        """
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
        Processes a single line of assembly code, removing whitespace and comments.

        Args:
            line: The raw line of assembly code.
            line_number: The original line number in the input file, used for error reporting.

        Returns:
            The processed line with whitespace and comments removed, or an empty string
            if the line was entirely a comment or whitespace.

        Raises:
            HackAssemblyError: If a single '/' character (not part of a '//' comment)
                               is found, indicating a syntax error.
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

    def first_pass(self, instruction: str, line_number: int) -> str:
        """
        Processes a single line during the assembler's first pass.

        Identifies and registers labels defined in the format `(LABEL)`.
        Adds valid labels to the symbol table, mapping the label name to the
        current effective instruction line number. Non-label lines increment
        the effective line number.

        Args:
            instruction: The instruction string from the source file.
            line_number: The original line number of the instruction in the source file.

        Returns:
            An empty string ("") if the instruction was a label definition,
            otherwise returns the original `instruction` string.

        Raises:
            HackAssemblyError: If a label is defined multiple times, or if a
                               label definition is malformed (e.g., missing
                               closing parenthesis).
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
        """
        Processes a single assembly instruction.

        Determines if the instruction is an A-instruction or a C-instruction
        and dispatches to the appropriate handler method.

        Args:
            instruction: The assembly instruction string.
            line_number: The line number of the instruction in the source file.

        Returns:
            An optional string representation of the processed instruction,
            or None if the instruction is empty.
        """
        if instruction == "":
            return None
        if instruction[0] == "@":
            return self.process_a_instruction(instruction, line_number)
        else:
            return self.process_c_instruction(instruction, line_number)

    def process_a_instruction(self, instruction: str, line_number: int) -> str:
        """
        Processes an A-instruction (starting with "@").

        An A-instruction can specify a decimal address or a symbol.
        If it's a decimal address, it's converted to binary.
        If it's a symbol, the symbol table is consulted. If the symbol is
        not found, it's added to the table starting from address 16.
        The resulting address is converted to a 16-bit binary string.

        Args:
            instruction: The A-instruction string (e.g., "@10", "@SCREEN").
            line_number: The line number in the source file for error reporting.

        Returns:
            A 16-bit binary string representing the A-instruction.

        Raises:
            HackAssemblyError: If the instruction is malformed (e.g., just "@")
                               or if the address is out of the 15-bit range.
        """
        address_part = instruction[1:]

        if not address_part:
            raise HackAssemblyError(
                f"Missing address for A instruction at {self._input_file}:{line_number}"
            )

        address_decimal: int

        try:
            # Attempt to parse as a decimal address
            address_decimal = int(address_part)
        except ValueError:
            # Not a decimal, must be a symbol
            symbol = address_part
            if symbol not in self._symbol_table:
                self._symbol_table[symbol] = 16 + self._symbol_count
                self._symbol_count += 1
            address_decimal = self._symbol_table[symbol]

        # Ensure the decimal address fits within 15 bits (0 to 32767)
        if not 0 <= address_decimal < (2**15):
            raise HackAssemblyError(
                f"Address {address_decimal} is out of range (0-32767) for A instruction at {self._input_file}:{line_number}"
            )

        # Convert decimal address to 15-bit binary string (excluding the leading '0')
        address_binary = format(address_decimal, "015b")
        # Prepend the required '0' bit for A-instructions to make it 16-bit
        return "0" + address_binary

    def process_c_instruction(self, instruction: str, line_number: int) -> str:
        """
        Converts a Hack Assembly C-instruction string into its 16-bit binary representation.

        A C-instruction does not start with "@" and has the format:
        dest=comp;jump
        where dest and jump are optional parts.

        Args:
            instruction: The C-instruction string to process (e.g., "D=M-1", "0;JMP").
            line_number: The line number of the instruction in the source file, used for error reporting.

        Returns:
            The 16-bit binary string representation of the instruction.

        Raises:
            HackAssemblyError: If the instruction is not a valid C-instruction (e.g.,
                               due to invalid comp, dest, or jump parts).
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
    """
    Parses command line arguments for input and output file paths.

    The function expects an input assembly file path and optionally an output path.
    If the output path is not provided, it defaults to a .hack file in the same
    directory as the input file, with the same stem.
    If the output path is a directory, the output .hack file is placed inside it.
    If the output path is a file, its extension is enforced to be .hack.

    Args:
        None (arguments are parsed from the command line via argparse).

    Returns:
        Tuple[Path, Path]: A tuple containing:
            - input_path (Path): The resolved absolute path to the input assembly file.
            - output_path (Path): The resolved absolute path to the output .hack file.

    Raises:
        RuntimeError: If a provided output file path does not have a '.hack' extension.
    """

    parser = argparse.ArgumentParser(description="Assemble Hack assembly code.")
    parser.add_argument(
        "input_file", type=Path, help="Path to the assembly code (.asm)"
    )
    parser.add_argument(
        "output_path",
        type=Path,
        nargs="?",
        help="Output file (.hack) or directory. Defaults to <input_stem>.hack in input directory.",
    )
    args = parser.parse_args()

    # 1. Resolve input path
    input_path: Path = args.input_file.resolve()
    input_stem = input_path.stem

    # 2. Determine the intended output path based on argument
    output_path: Path

    if args.output_path is None:
        # Case 1: No output path provided -> default to <input_dir>/<input_stem>.hack
        output_path = input_path.with_name(f"{input_stem}.hack")
    else:
        out = args.output_path
        if out.is_dir():
            # Case 2: Output path is a directory -> place <input_stem>.hack inside
            output_path = out / f"{input_stem}.hack"
        else:
            # Case 3: Output path is a file -> enforce .hack extension
            if out.suffix != ".hack":
                parser.error(f"Output file extension must be .hack, not '{out.suffix}'")
            output_path = out

    # 3. Resolve the final determined output path
    # This ensures the path is absolute and symbolic links are followed.
    output_path = output_path.resolve()

    return input_path, output_path


def process_assembly(input_file: Path) -> List[str]:
    """
    Processes the assembly file in two passes: symbol table construction and instruction translation.

    The first pass reads the file to identify and register labels, building
    the symbol table with correct instruction addresses. The second pass
    iterates through the cleaned instructions (excluding labels and comments)
    and translates each A-instruction or C-instruction into its 16-bit binary
    representation using the populated symbol table.

    Args:
        input_file (Path): The path to the input assembly file (.asm).

    Returns:
        List[str]: A list of 16-bit binary instruction strings, one for each
                   effective instruction in the input file.

    Raises:
        FileNotFoundError: If the input_file does not exist.
        IOError: If there's an error reading the input file.
        HackAssemblyError: If any syntax or semantic error is found in the assembly code
                           during processing (e.g., invalid syntax, duplicate labels,
                           undefined symbols after first pass, address out of range).
    """
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
    except (HackAssemblyError, FileNotFoundError, IOError) as e:
        print(f"Error: {type(e).__name__} - {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__} - {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Assembly successful. Output written to {output_file}")

if __name__ == "__main__":
    main()
