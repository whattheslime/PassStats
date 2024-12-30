#!/usr/bin/env python3
# =============================================================================
# Author:       Sélim Lanouar (@whattheslime)
# Creation:     November 25th 2023
# Description:  Simple script that analyses account passwords and generates 
#               hashcat masks.
# -----------------------------------------------------------------------------
# Refrences:    https://github.com/iphelix/pack
#               https://hashcat.net/hashcat/
# -----------------------------------------------------------------------------
# Usage:        python3 pass_stats.py -h
# =============================================================================
from argparse import ArgumentParser
from string import ascii_lowercase, ascii_uppercase, digits as ascii_digits
from pathlib import Path


# Constants
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
NONE_TYPE = type(None)

# Accounts related statistics
most_used = {}
login_pass_case = 0
login_pass_nocase = 0
lm_hashes = 0

# Global passwords statistics
nb_passwords = 0
lengths = {}

min_digits = None
max_digits = None

min_lowers = None
max_lowers = None

min_specials = None
max_specials = None

min_uppers = None
max_uppers = None

charsets = {}
masks = {}


class Password:
    """Class that describe password statistics."""

    value = None
    hash = None
    length = 0

    digits = 0
    lowers = 0
    specials = 0
    uppers = 0

    mask = ""
    charset = ""

    def __init__(self, password: str, hash: str = ""):
        global nb_passwords
        global lengths
        global min_digits
        global max_digits
        global min_lowers
        global max_lowers
        global min_specials
        global max_specials
        global min_uppers
        global max_uppers
        global charsets
        global masks

        nb_passwords += 1
        self.value = password
        self.hash = hash

        if password.startswith("$HEX["):
            byte_string = bytes.fromhex(password[5:-1])
            password = byte_string.decode("latin")

        self.length = len(password)
        lengths.setdefault(self.length, 0)
        lengths[self.length] += 1

        charset = set()
        for character in password:
            if character in ascii_digits:
                self.digits += 1
                charset.add("digit")
                self.mask += "?d"
            elif character in ascii_lowercase:
                self.lowers += 1
                charset.add("lower")
                self.mask += "?l"
            elif character in ascii_uppercase:
                self.uppers += 1
                charset.add("upper")
                self.mask += "?u"
            else:
                self.specials += 1
                charset.add("special")
                self.mask += "?s"

        if isinstance(min_digits, NONE_TYPE) or min_digits > self.digits:
            min_digits = self.digits

        if isinstance(max_digits, NONE_TYPE) or max_digits < self.digits:
            max_digits = self.digits

        if isinstance(min_lowers, NONE_TYPE) or min_lowers > self.lowers:
            min_lowers = self.lowers

        if isinstance(max_lowers, NONE_TYPE) or max_lowers < self.lowers:
            max_lowers = self.lowers

        if isinstance(min_uppers, NONE_TYPE) or min_uppers > self.uppers:
            min_uppers = self.uppers

        if isinstance(max_uppers, NONE_TYPE) or max_uppers < self.uppers:
            max_uppers = self.uppers

        if isinstance(min_specials, NONE_TYPE) or min_specials > self.specials:
            min_specials = self.specials

        if isinstance(max_specials, NONE_TYPE) or max_specials < self.specials:
            max_specials = self.specials

        masks.setdefault(self.mask, 0)
        masks[self.mask] += 1

        self.charset = " / ".join(charset)
        charsets.setdefault(self.charset, 0)
        charsets[self.charset] += 1


def percent(number: int, total: int, invert: bool = False) -> str:
    """Calculate and format percentages."""
    if invert:
        return f"{round(number / total * 100, 2)}% ({number})"
    else:
        return f"{number} ({round(number / total * 100, 2)}%)"


def table(table: list[list]) -> str:
    """Return a table in markdown compliant string."""
    if not table:
        return ""

    col_widths = [max(len(str(item)) for item in col) for col in zip(*table)]

    def format_row(row):
        content = [
            f"{str(item):<{col_widths[i]}}" for i, item in enumerate(row)
        ]
        return f"| {' | '.join(content)} |"

    header = format_row(table[0])
    separator = f"|-{'-|-'.join('-' * width for width in col_widths)}-|"
    body = "\n".join(format_row(row) for row in table[1:])

    return f"{header}\n{separator}\n{body}\n"


def top_table(title: str, elements: dict, total: int, top: int) -> str:
    """Calculate elements occurences and return a table."""
    elements = [
        (element[0], element[1])
        for element in sorted(
            elements.items(), key=lambda item: item[1], reverse=True
        )
    ]

    if top:
        elements = elements[:top]
        title = f"{title} (Top {top})"

    header = [(title, "Occurences")]
    rows = [(element, percent(number, total)) for element, number in elements]

    return table(header + rows)


def load_dict(path: Path, separator: str = ":", ntds: bool = False):
    """Loading a dictionary file and yield keys, values line-by-line."""
    global lm_hashes
    nb_line = 1
    with open(path, "r", encoding="latin-1") as file:
        for line in iter(file.readline, ""):
            if ntds and line.count(separator) >= 4:
                key, _, lm_hash, value, _ = line.split(separator, 4)
                if lm_hash != EMPTY_LM:
                    lm_hashes += 1
            elif line.count(separator) == 1:
                key, value = line.split(separator, 1)
            else:
                raise ValueError(
                    f'"{separator}" not found in "{path}", line {nb_line}'
                )
            yield key, value.strip("\n")
            nb_line += 1


def load_list(path: Path):
    """Loading a list file and yield values line-by-line."""
    with open(path, "r", encoding="latin-1") as file:
        for line in iter(file.readline, ""):
            yield line.strip("\n")


def parse_args():
    """Parse user arguments."""
    parser = ArgumentParser(
        description="Simple script that analyses account passwords and "
        "generates hashcat masks"
    )
    parser.add_argument(
        "passwords",
        type=Path,
        help="path to a file containing a password on each line",
    )

    input_group = parser.add_argument_group("input")
    input_ex_group = input_group.add_mutually_exclusive_group()
    input_ex_group.add_argument(
        "--hashes",
        action="store_true",
        help="indicates use of a list of HASH:PASS in the passwords argument",
    )
    input_ex_group.add_argument(
        "--users",
        type=Path,
        help="path to a file containing a USER:HASH on each line, "
        "the use of HASH:PASS format for passwords flag is mandatory",
    )
    input_group.add_argument(
        "--ntds",
        action="store_true",
        help="indicates that '--users' flag is an ntds.dit dump format",
    )

    output_group = parser.add_argument_group("output")
    output_ex_group = output_group.add_mutually_exclusive_group()
    output_ex_group.add_argument(
        "--top",
        type=int,
        default=10,
        help="define the number of passwords and masks to display "
        "(default: 10) (all: 0)",
    )
    output_ex_group.add_argument(
        "--masks",
        action="store_true",
        help="display passwords masks by with most used first",
    )
    output_ex_group.add_argument(
        "--join",
        action="store_true",
        help="join users and password files to the following format: "
        "USER:HASH:PASS",
    )

    args = parser.parse_args()

    if args.ntds and not args.users:
        parser.error("argument --ntds: requires argument --users")

    if args.join and not args.users:
        parser.error("argument --join: requires argument --users")

    return args


def main():
    """Entry point"""
    global most_used
    global login_pass_case
    global login_pass_nocase

    args = parse_args()

    # Process passwords statistics
    users_dict = {}
    if args.users:
        hashes_dict = {
            hash: password for hash, password in load_dict(args.passwords)
        }
        for user, hash in load_dict(args.users, ntds=args.ntds):
            password = hashes_dict.get(hash, None)
            users_dict[user] = (
                Password(password, hash=hash)
                if isinstance(password, str)
                else None
            )
    elif args.hashes:
        for hash, password in load_dict(args.passwords):
            Password(password, hash=hash)
    else:
        for password in load_list(args.passwords):
            Password(password)

    top = args.top

    # Users metrics
    accounts = 0
    accounts_passwords = 0

    machines = 0
    machines_passwords = 0

    login_pass_case = 0
    login_pass_nocase = 0

    for user, password in users_dict.items():
        if args.join:
            if password:
                print(":".join((user, password.hash, password.value)))
            continue

        accounts += 1

        if user.endswith("$"):
            machines += 1
            if password:
                machines_passwords += 1

        if password:
            accounts_passwords += 1

            most_used.setdefault(password.value, 0)
            most_used[password.value] += 1

            login_pass_case += int(user == password.value)
            login_pass_nocase += int(user.lower() == password.value.lower())

    if args.masks:
        for mask in sorted(masks.keys(), key=lambda x: x[1], reverse=True):
            print(mask)
        return

    if args.join:
        return

    # Display metrics
    print("\nPasswords Analysis\n==================\n")

    if accounts:
        account_table = [
            ("Accounts", "Total", "Recovered passwords"),
            ("All", accounts, percent(accounts_passwords, accounts)),
            (
                "Users",
                percent(accounts - machines, accounts),
                percent(
                    accounts_passwords - machines_passwords,
                    accounts - machines,
                ),
            ),
        ]

        if machines:
            account_table.append(
                (
                    "Machines",
                    percent(machines, accounts),
                    percent(machines_passwords, machines),
                )
            )

        print(table(account_table))

        bad_usage_table = [
            ("Bad usages", "Count"),
        ]

        if args.ntds:
            bad_usage_table.append(
                ("Non-empty LM hashes", percent(lm_hashes, accounts))
            )

        bad_usage_table.append(
            ("Login = Pass (Same Case)", percent(login_pass_case, accounts))
        )
        bad_usage_table.append(
            (
                "Login = Pass (Different Case)",
                percent(login_pass_nocase, accounts),
            )
        )
        print(table(bad_usage_table))

        print(top_table("Most used passwords", most_used, nb_passwords, top))

    complexity_table = (
        ("Passwords complexity", "Minimum", "Maximum"),
        ("Digit", min_digits, max_digits),
        ("Lower case", min_lowers, max_lowers),
        ("Upper case", min_uppers, max_uppers),
        ("Special", min_specials, max_specials),
    )

    print(table(complexity_table))

    print(top_table("Character sets", charsets, nb_passwords, 0))

    print(top_table("Passwords lengths", lengths, nb_passwords, top))

    print(top_table("Passwords masks", masks, nb_passwords, top))


if __name__ == "__main__":
    main()
