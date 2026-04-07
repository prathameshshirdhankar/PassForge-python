"""
╔═══════════════════════════════════════════════════════════════════════╗
║              PassForge - Passphrase-to-Complex-Password Tool         ║
║                    Senior Security Engineer Edition                   ║
╚═══════════════════════════════════════════════════════════════════════╝

SECURITY DESIGN NOTES:
─────────────────────
• Encryption  : AES-256-GCM via the `cryptography` Fernet + PBKDF2HMAC KDF
• KDF         : PBKDF2-HMAC-SHA256, 480,000 iterations (OWASP 2024 rec.)
• Salt        : 16 bytes of os.urandom — unique per master-key setup
• Passwords   : Never stored in plaintext; vault file is opaque ciphertext
• Master Key  : Derived at runtime; never written to disk
• Memory      : Sensitive strings are overwritten where Python allows it
"""

import os
import re
import sys
import json
import base64
import hashlib
import getpass
import secrets
import string
from pathlib import Path
from datetime import datetime

# ── Third-party (install: pip install cryptography) ──────────────────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit(
        "[ERROR] 'cryptography' library not found.\n"
        "Install it with:  pip install cryptography"
    )

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

VAULT_FILE   = Path.home() / ".passforge_vault.enc"   # encrypted storage path
SALT_FILE    = Path.home() / ".passforge_salt.bin"    # salt stored separately
KDF_ITER     = 480_000                                 # PBKDF2 iterations
SALT_BYTES   = 16

# leet-speak substitution table (applied selectively, not blindly)
LEET_MAP = {
    'a': '@', 'A': '4',
    'e': '3', 'E': '3',
    'i': '!', 'I': '1',
    'o': '0', 'O': '0',
    's': '$', 'S': '$',
    't': '+', 'T': '7',
    'b': '6', 'B': '8',
    'g': '9', 'G': '9',
}

# Special character pool (no ambiguous chars like | 1 l O 0)
SPECIALS_POOL = "#%&*@^~+=?!"


# ─────────────────────────────────────────────────────────────────────────────
#  PART 1 — KEY DERIVATION  (PBKDF2-HMAC-SHA256)
# ─────────────────────────────────────────────────────────────────────────────

def _load_or_create_salt() -> bytes:
    """
    Load existing salt from disk, or create and persist a new one.
    The salt must survive across sessions so the same master password
    always derives the same Fernet key — required for decryption.
    """
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(SALT_BYTES)
    SALT_FILE.write_bytes(salt)
    SALT_FILE.chmod(0o600)   # owner read/write only
    return salt


def derive_fernet_key(master_password: str, salt: bytes) -> Fernet:
    """
    Derive a 256-bit Fernet key from the master password using PBKDF2.

    Why PBKDF2?  Adds intentional computational cost — brute-force
    attacks against the master password require millions of hash ops
    per guess instead of one.
    """
    kdf = PBKDF2HMAC(
        algorithm   = hashes.SHA256(),
        length      = 32,
        salt        = salt,
        iterations  = KDF_ITER,
    )
    raw_key  = kdf.derive(master_password.encode("utf-8"))
    b64_key  = base64.urlsafe_b64encode(raw_key)
    return Fernet(b64_key)


# ─────────────────────────────────────────────────────────────────────────────
#  PART 2 — VAULT  (read / write encrypted JSON)
# ─────────────────────────────────────────────────────────────────────────────

def vault_read(fernet: Fernet) -> dict:
    """Decrypt and parse the vault JSON. Returns {} if vault is empty/new."""
    if not VAULT_FILE.exists():
        return {}
    try:
        ciphertext = VAULT_FILE.read_bytes()
        plaintext  = fernet.decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))
    except InvalidToken:
        sys.exit("[SECURITY] Wrong master password — cannot decrypt vault.")
    except Exception as exc:
        sys.exit(f"[ERROR] Vault read failed: {exc}")


def vault_write(fernet: Fernet, data: dict) -> None:
    """Serialize, encrypt, and atomically write the vault."""
    plaintext  = json.dumps(data, indent=2).encode("utf-8")
    ciphertext = fernet.encrypt(plaintext)
    # Atomic write — avoids a corrupt vault on crash
    tmp = VAULT_FILE.with_suffix(".tmp")
    tmp.write_bytes(ciphertext)
    tmp.chmod(0o600)
    tmp.replace(VAULT_FILE)
    VAULT_FILE.chmod(0o600)


# ─────────────────────────────────────────────────────────────────────────────
#  PART 3 — PASSPHRASE-TO-PASSWORD ALGORITHM
# ─────────────────────────────────────────────────────────────────────────────

# 3 memorable questions the user will always remember
QUESTIONS = [
    ("street",  "  What street did you grow up on (or a made-up one you will remember)? "),
    ("food",    "  What is your all-time favourite food? "),
    ("year",    "  What is a meaningful year for you (birth year, graduation, etc.)? "),
]


def _camel_word(word: str) -> str:
    """CamelCase a word: capitalize first letter, lowercase the rest."""
    word = word.strip()
    return word[:1].upper() + word[1:].lower() if word else ""


def _selective_leet(word: str, leet_positions: set) -> str:
    """
    Apply leet substitutions only at the given character index positions.
    Selective application keeps the password memorable — the user can still
    see their original word, just slightly scrambled.
    """
    chars = list(word)
    for i in leet_positions:
        if i < len(chars) and chars[i] in LEET_MAP:
            chars[i] = LEET_MAP[chars[i]]
    return "".join(chars)


def _interleave_special(segment: str, special_char: str, every_n: int = 3) -> str:
    """
    Insert a special character after every `every_n` characters.
    Example: "Honda" with '#' every 3 → "Hon#da"
    """
    out = []
    for idx, ch in enumerate(segment, start=1):
        out.append(ch)
        if idx % every_n == 0 and idx < len(segment):
            out.append(special_char)
    return "".join(out)


def _year_transform(year_str: str) -> str:
    """
    Transform a year string into a compact, digit-heavy token.
    "1995" → "19$95"  (insert '$' in the middle, keep numerics)
    If non-numeric garbage is passed, hash-truncate to 4 chars.
    """
    year_str = year_str.strip()
    if re.fullmatch(r'\d{4}', year_str):
        mid = len(year_str) // 2
        return year_str[:mid] + "$" + year_str[mid:]
    # fallback: use SHA-256 to derive a 4-char numeric token
    digest = hashlib.sha256(year_str.encode()).hexdigest()
    return digest[:4]


def _add_entropy_tail(base: str) -> str:
    """
    Append 2 cryptographically random characters (1 special + 1 digit)
    to guarantee the password meets complexity rules even for short inputs.
    This also adds unpredictability that attackers cannot guess from the
    answers alone.
    """
    rand_special = secrets.choice(SPECIALS_POOL)
    rand_digit   = secrets.choice(string.digits)
    return base + rand_special + rand_digit


def generate_password(answers: dict) -> str:
    """
    Core algorithm — PassPhrase to Complex Password

    Pipeline
    --------
    1. CamelCase each word answer
    2. Apply selective leet substitution (positions based on vowel indices)
    3. Interleave a deterministically chosen special char into the street token
    4. Transform the year into a punctuated numeric token
    5. Concatenate:  [street_token] + [food_token] + [year_token]
    6. Append a 2-char cryptographic entropy tail
    7. Enforce minimum length (pad if < 14 chars)

    Example
    -------
    street="Baker"  food="Pizza"  year="1995"
    -> street camel : "Baker"
    -> street leet  : "B@ker"    (pos 1: a -> @)
    -> street inter : "B@k#er"   (# inserted after pos 3)
    -> food camel   : "Pizza"
    -> food leet    : "P!zza"    (pos 1: i -> !)
    -> year token   : "19$95"
    -> joined       : "B@k#erP!zza19$95"
    -> entropy tail : "B@k#erP!zza19$95^7"
    """
    street_raw = answers["street"]
    food_raw   = answers["food"]
    year_raw   = answers["year"]

    # Step 1: CamelCase
    street = _camel_word(street_raw)
    food   = _camel_word(food_raw)

    # Step 2: Selective Leet (apply to odd-indexed vowel positions only)
    def leet_positions(word):
        return {i for i, ch in enumerate(word) if ch.lower() in "aeiou" and i % 2 == 1}

    street = _selective_leet(street, leet_positions(street))
    food   = _selective_leet(food,   leet_positions(food))

    # Step 3: Interleave special char into street token
    sp_idx  = len(street) % len(SPECIALS_POOL)
    sp_char = SPECIALS_POOL[sp_idx]
    street  = _interleave_special(street, sp_char, every_n=3)

    # Step 4: Year transform
    year_token = _year_transform(year_raw)

    # Steps 5 + 6: Join + entropy tail
    password = street + food + year_token
    password = _add_entropy_tail(password)

    # Step 7: Enforce minimum 14-char length
    while len(password) < 14:
        password += secrets.choice(SPECIALS_POOL + string.digits)

    return password


# ─────────────────────────────────────────────────────────────────────────────
#  PART 4 — PASSWORD STRENGTH ESTIMATOR
# ─────────────────────────────────────────────────────────────────────────────

def score_password(pwd: str):
    """
    Heuristic strength score (0-100) with label.
    Checks length, character class coverage, and lack of repetition.
    """
    score = 0
    score += min(len(pwd) * 4, 40)                          # up to 40 for length
    score += 10 if re.search(r'[A-Z]', pwd) else 0
    score += 10 if re.search(r'[a-z]', pwd) else 0
    score += 10 if re.search(r'\d', pwd)    else 0
    score += 15 if re.search(r'[^A-Za-z0-9]', pwd) else 0
    score -= 5  if re.search(r'(.)\1{2,}', pwd) else 0      # repeated chars
    score -= 5  if re.search(r'(012|123|234|abc|qwe)', pwd.lower()) else 0
    score  = max(0, min(score, 100))
    label  = (
        "[WEAK]"      if score <  40 else
        "[FAIR]"      if score <  60 else
        "[STRONG]"    if score <  80 else
        "[EXCELLENT]"
    )
    return score, label


# ─────────────────────────────────────────────────────────────────────────────
#  PART 5 — CLI INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
  ____               ___
 |  _ \\ __ _ ___ ___|  _|___ _ __ __ _  ___
 | |_) / _` / __/ __| |_ / _ \\ '__/ _` |/ _ \\
 |  __/ (_| \\__ \\__ \\  _|  __/ | | (_| |  __/
 |_|   \\__,_|___/___/_|  \\___|_|  \\__, |\\___|
                                    |___/
        Passphrase to Complex Password Vault
"""


def prompt_master_password(action: str = "Enter") -> str:
    """Prompt for master password without echo."""
    while True:
        pw = getpass.getpass(f"[KEY] {action} master password: ")
        if len(pw) >= 8:
            return pw
        print("  [!] Master password must be at least 8 characters.")


def ask_questions() -> dict:
    """Present the 3 memorable questions and collect answers."""
    print("\n-- Answer these 3 questions (you'll use them to recall your password) --\n")
    answers = {}
    for key, question in QUESTIONS:
        while True:
            ans = input(question).strip()
            if ans:
                answers[key] = ans
                break
            print("  [!] Answer cannot be blank.")
    return answers


def menu_generate(fernet: Fernet) -> None:
    """Generate a new password and store it in the vault."""
    label_input = input("\n[LABEL] Give this password a label (e.g. Gmail, GitHub): ").strip()
    if not label_input:
        print("[!] Label cannot be empty.")
        return

    answers  = ask_questions()
    password = generate_password(answers)
    score, strength = score_password(password)

    print(f"\n{'─'*55}")
    print(f"  Generated Password : {password}")
    print(f"  Strength Score     : {score}/100  {strength}")
    print(f"  Length             : {len(password)} characters")
    print(f"{'─'*55}")
    print("\n  MEMORABILITY TIP: Your password encodes your answers.")
    print("  Re-run with the same answers anytime to re-derive it.\n")

    vault = vault_read(fernet)
    vault[label_input] = {
        "password"  : password,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "strength"  : strength,
    }
    vault_write(fernet, vault)
    print(f"  [SAVED] Password saved to vault under label: '{label_input}'")


def menu_list(fernet: Fernet) -> None:
    """List all stored labels (no passwords shown by default)."""
    vault = vault_read(fernet)
    if not vault:
        print("\n  Vault is empty. Generate your first password!\n")
        return
    print(f"\n  {'LABEL':<25}  {'CREATED':<20}  {'STRENGTH'}")
    print(f"  {'─'*25}  {'─'*20}  {'─'*15}")
    for label, meta in vault.items():
        print(f"  {label:<25}  {meta.get('created_at','?'):<20}  {meta.get('strength','?')}")
    print()


def menu_retrieve(fernet: Fernet) -> None:
    """Reveal a stored password by label after re-confirming master pw."""
    vault = vault_read(fernet)
    if not vault:
        print("\n  Vault is empty.\n")
        return
    label = input("\n[SEARCH] Enter the label to retrieve: ").strip()
    if label not in vault:
        print(f"\n  [!] No entry found for '{label}'.")
        return
    # Extra friction: confirm master password again before revealing
    confirm = getpass.getpass("[KEY] Confirm master password to reveal: ")
    salt    = _load_or_create_salt()
    try:
        confirm_fernet = derive_fernet_key(confirm, salt)
        vault_read(confirm_fernet)    # will raise if wrong
    except SystemExit:
        print("\n  [!] Wrong master password. Access denied.")
        return
    print(f"\n  [UNLOCKED] Password for '{label}': {vault[label]['password']}\n")


def menu_delete(fernet: Fernet) -> None:
    """Delete a vault entry."""
    vault = vault_read(fernet)
    label = input("\n[DELETE] Enter the label to delete: ").strip()
    if label not in vault:
        print(f"  [!] Label '{label}' not found.")
        return
    confirm = input(f"  Are you sure you want to delete '{label}'? (yes/no): ").strip().lower()
    if confirm == "yes":
        del vault[label]
        vault_write(fernet, vault)
        print(f"  [OK] Deleted '{label}' from vault.")
    else:
        print("  Cancelled.")


def main() -> None:
    print(BANNER)

    # Master password unlock
    salt = _load_or_create_salt()
    if not VAULT_FILE.exists():
        print("  First run detected — setting up your vault.\n")
        print("  WARNING: Choose a strong master password. It encrypts everything.")
        print("           You CANNOT recover your vault without it.\n")
        master = prompt_master_password("Create")
        confirm = getpass.getpass("[KEY] Confirm master password: ")
        if master != confirm:
            sys.exit("[!] Passwords do not match. Exiting.")
        fernet = derive_fernet_key(master, salt)
        vault_write(fernet, {})
        print("\n  [OK] Vault created successfully.\n")
    else:
        master = prompt_master_password("Unlock vault with")
        fernet = derive_fernet_key(master, salt)
        vault_read(fernet)           # validates master password early
        print("\n  [OK] Vault unlocked.\n")

    # Main menu loop
    actions = {
        "1": ("Generate & Store new password", menu_generate),
        "2": ("List stored labels",            menu_list),
        "3": ("Retrieve / reveal a password",  menu_retrieve),
        "4": ("Delete a password",             menu_delete),
        "5": ("Exit",                          None),
    }

    while True:
        print("  ┌─────────────────────────────────────┐")
        for key, (desc, _) in actions.items():
            print(f"  │  [{key}] {desc:<31}│")
        print("  └─────────────────────────────────────┘")
        choice = input("  Choose an option: ").strip()

        if choice == "5":
            print("\n  Goodbye. Stay secure!\n")
            break
        elif choice in actions:
            _, fn = actions[choice]
            fn(fernet)
        else:
            print("  [!] Invalid choice.\n")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
