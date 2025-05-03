from pathlib import Path

import pytest
from my_hack_assembler import process_assembly

CASE_DIR = Path(__file__).parent / "cases"


@pytest.mark.parametrize("asm_path", sorted(CASE_DIR.glob("*.asm")))
def test_cases(asm_path: Path):
    """
    For each .asm in cases/, assemble it and compare
    line-by-line to the corresponding .hack.
    """
    # 1. read expected lines
    hack_path = asm_path.with_suffix(".hack")
    expected = hack_path.read_text(encoding="utf-8").splitlines()

    # 2. run assembler (in-process)
    actual = process_assembly(asm_path)

    # 3. assert exact match
    assert actual == expected, (
        f"Mismatch for {asm_path.name}:\n"
        f" expected ({len(expected)} lines):\n"
        f"{expected!r}\n"
        f" got ({len(actual)} lines):\n"
        f"{actual!r}"
    )
