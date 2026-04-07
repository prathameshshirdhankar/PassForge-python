# PassForge 🔐

> **Passphrase → Complex Password Vault**
> A memorable-yet-unbreakable password generator with an encrypted local vault — built by Prathamesh Shirdhankar, powered entirely by Python's standard library + one dependency.

```
  ____               ___
 |  _ \ __ _ ___ ___|  _|___ _ __ __ _  ___
 | |_) / _` / __/ __| |_ / _ \ '__/ _` |/ _ \
 |  __/ (_| \__ \__ \  _|  __/ | | (_| |  __/
 |_|   \__,_|___/___/_|  \___|_|  \__, |\___|
                                    |___/
        Passphrase to Complex Password Vault
```

---

## Why PassForge?

Most password generators produce strings like `xK#9!mPq2$Lv` — technically strong, practically impossible to remember. PassForge takes the opposite approach:

**You answer 3 questions you'll never forget. The algorithm turns your answers into a complex password. The result is stored in an AES-256 encrypted vault on your machine — never in the cloud.**

```
Inputs:   street="Baker"   food="Pizza"   year="1995"
Output:   B@k#erP!zza19$95^7
          └─────────────────┘└──┘
          Derived from answers   Random entropy tail
```

The password *encodes* your memory, so even if you lose the vault file, you can re-derive the deterministic core just by answering the same questions again.

---

## Features

- **Passphrase-to-Password algorithm** — 7-stage transformation pipeline (CamelCase → selective leet → special-char interleaving → year punctuation → entropy tail)
- **AES-256 encrypted vault** — via Python `cryptography` Fernet; stores unlimited labelled passwords
- **PBKDF2-HMAC-SHA256 key derivation** — 480,000 iterations (OWASP 2024 recommendation), brute-force resistant
- **Unique per-install salt** — 16 bytes of `os.urandom`; rainbow tables are useless
- **Re-authentication before reveal** — master password re-confirmed every time a password is shown
- **Atomic vault writes** — write-to-temp-then-replace prevents vault corruption on crash
- **Heuristic strength scorer** — 0–100 score with Weak / Fair / Strong / Excellent label
- **No cloud, no accounts** — everything lives in two hidden files in your home directory
- **Single-file script** — `passforge.py`, ~460 lines, one third-party dependency

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.8 or higher |
| `cryptography` | Any recent version (`pip install cryptography`) |

That is the complete dependency list.

---

## Installation

### Option A — Clone the repository

```bash
git clone https://github.com/prathameshshirdhankar/passforge.git
cd passforge
pip install cryptography
python passforge.py
```


### Option B — Virtual environment (recommended for production use)

```bash
git clone https://github.com/prathameshshirdhankar/passforge.git
cd passforge
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install cryptography
python passforge.py
```

---

## First Run

On first launch, PassForge detects that no vault exists and guides you through setup:

```
  ____               ___
 |  _ \ __ _ ___ ___|  _|___ ...

  First run detected — setting up your vault.

  WARNING: Choose a strong master password. It encrypts everything.
           You CANNOT recover your vault without it.

[KEY] Create master password:
[KEY] Confirm master password:

  [OK] Vault created successfully.

  ┌─────────────────────────────────────┐
  │  [1] Generate & Store new password  │
  │  [2] List stored labels             │
  │  [3] Retrieve / reveal a password   │
  │  [4] Delete a password              │
  │  [5] Exit                           │
  └─────────────────────────────────────┘
  Choose an option:
```

Two files are created in your home directory:

| File | Purpose | Permissions |
|---|---|---|
| `~/.passforge_vault.enc` | AES-256 encrypted password vault | `600` (owner only) |
| `~/.passforge_salt.bin` | PBKDF2 salt (16 random bytes) | `600` (owner only) |

> **Important:** Back up both files together. The vault cannot be decrypted without its salt, and the salt is useless without the vault.

---

## Usage Walkthrough

### 1. Generate and store a new password

Select option `[1]`. You are prompted for a label and then 3 questions:

```
[LABEL] Give this password a label (e.g. Gmail, GitHub): GitHub

-- Answer these 3 questions (you'll use them to recall your password) --

  What street did you grow up on (or a made-up one you will remember)? Baker
  What is your all-time favourite food? Pizza
  What is a meaningful year for you (birth year, graduation, etc.)? 1995

───────────────────────────────────────────────────────
  Generated Password : B@k#erP!zza19$95^7
  Strength Score     : 95/100  [EXCELLENT]
  Length             : 18 characters
───────────────────────────────────────────────────────

  MEMORABILITY TIP: Your password encodes your answers.
  Re-run with the same answers anytime to re-derive it.

  [SAVED] Password saved to vault under label: 'GitHub'
```

### 2. List stored labels

Select option `[2]`. Labels, creation timestamps, and strength ratings are shown. **Passwords are never displayed here.**

```
  LABEL                      CREATED               STRENGTH
  ─────────────────────────  ────────────────────  ───────────────
  GitHub                     2025-07-10T14:32:05   [EXCELLENT]
  Gmail                      2025-07-10T14:35:18   [STRONG]
  BankOfAmerica              2025-07-10T14:38:44   [EXCELLENT]
```

### 3. Retrieve / reveal a password

Select option `[3]`. You must re-enter your master password before any password is shown — even though you are already "logged in" to the session.

```
[SEARCH] Enter the label to retrieve: GitHub
[KEY] Confirm master password to reveal:

  [UNLOCKED] Password for 'GitHub': B@k#erP!zza19$95^7
```

### 4. Delete a password

Select option `[4]`. Prompts for the label and asks for explicit confirmation.

```
[DELETE] Enter the label to delete: Gmail
  Are you sure you want to delete 'Gmail'? (yes/no): yes
  [OK] Deleted 'Gmail' from vault.
```

---

## The Algorithm — How Passwords Are Built

PassForge uses a deterministic 7-stage transformation pipeline that converts three personal answers into a complex password. Six of the seven stages are deterministic (same input → same output). Stage 6 adds a cryptographically random tail for unpredictability.

### Full Pipeline with Example

**Input answers:**
- Street: `Baker`
- Food: `Pizza`
- Year: `1995`

---

#### Stage 1 — CamelCase normalisation

Each word answer is capitalised: first letter uppercase, remainder lowercase. This ensures consistent casing regardless of how the user typed the answer.

```
"baker" → "Baker"
"PIZZA" → "Pizza"
"baker street" → "Baker street"  (only first character is capitalised)
```

---

#### Stage 2 — Selective leet substitution

Only odd-indexed vowel positions in the word are substituted using the leet map. "Selective" is the key word — applying leet to every vowel produces predictable, easy-to-reverse patterns. Applying it to only every other vowel (index 1, 3, 5…) keeps the word recognisable but non-trivial to reverse.

**Leet map used:**

| Original | Substitution | Original | Substitution |
|---|---|---|---|
| `a` | `@` | `A` | `4` |
| `e` | `3` | `E` | `3` |
| `i` | `!` | `I` | `1` |
| `o` | `0` | `O` | `0` |
| `s` | `$` | `S` | `$` |
| `t` | `+` | `T` | `7` |
| `b` | `6` | `B` | `8` |
| `g` | `9` | `G` | `9` |

```
"Baker"  → vowels at positions: a=1, e=3
           odd positions hit: 1 (a→@), 3 (e→3) … but 'e' isn't in Baker
           result: "B@ker"   (only 'a' at index 1 is odd)

"Pizza"  → vowels: i=1, a=3
           odd positions: 1 (i→!), 3 (a→@) … 'a' at 3, but pos 3 in "Pizza" is 'z'
           result: "P!zza"   (only 'i' at index 1 qualifies)
```

---

#### Stage 3 — Special character interleaving (street token only)

A special character is inserted into the street token after every 3rd character. The character is chosen **deterministically** from the pool `#%&*@^~+=?!` using `len(street) % pool_length` — meaning the same street word always picks the same character, but different words pick different ones.

```
street = "B@ker"   length = 5
special_index = 5 % 11 = 5   →   pool[5] = '#'
Insert '#' after every 3rd char (but not at the end):
"B@k" + "#" + "er"  =  "B@k#er"
```

The interleaving step only applies to the **street** token, not food. Applying it to all tokens would make the password unwieldy; applying it to one creates asymmetry that increases complexity without destroying memorability.

---

#### Stage 4 — Year transformation

A 4-digit year is split in half with a `$` character inserted in the middle.

```
"1995"  →  "19" + "$" + "95"  =  "19$95"
```

Non-4-digit inputs (text, partial years) fall back to a SHA-256 truncation: the first 4 hex characters of `SHA-256(input)` are used instead. This is a silent graceful degradation — the user gets a valid token, though less memorable.

---

#### Stage 5 — Concatenation

The three transformed tokens are joined in order: street → food → year.

```
"B@k#er"  +  "P!zza"  +  "19$95"
=  "B@k#erP!zza19$95"
```

---

#### Stage 6 — Cryptographic entropy tail

Two characters are appended using Python's `secrets` module (a CSPRNG backed by `os.urandom`):
- 1 random special character from `#%&*@^~+=?!`
- 1 random digit from `0–9`

```
"B@k#erP!zza19$95"  +  "^"  +  "7"
=  "B@k#erP!zza19$95^7"
```

This tail is **non-deterministic**. It changes on every run. Its purpose is to ensure:
1. An attacker who knows the answers cannot derive the exact stored password
2. The password always contains at least one special character and one digit (complexity guarantee)
3. Unpredictability even against targeted dictionary attacks seeded with personal info

---

#### Stage 7 — Minimum length enforcement

If the assembled password is shorter than 14 characters (possible with very short answers), additional random characters from the special/digit pool are appended until the minimum is reached.

---

### Algorithm Summary Table

| Stage | Input | Operation | Output |
|---|---|---|---|
| 1 | Raw answers | CamelCase | `Baker`, `Pizza` |
| 2 | CamelCased words | Selective leet at odd vowel indices | `B@ker`, `P!zza` |
| 3 | Street token | Interleave special char every 3 chars | `B@k#er` |
| 4 | Year string | Split with `$` in the middle | `19$95` |
| 5 | All tokens | Concatenation | `B@k#erP!zza19$95` |
| 6 | Assembled password | Append CSPRNG special + digit | `B@k#erP!zza19$95^7` |
| 7 | Final password | Pad to 14 chars if needed | _(unchanged in this example)_ |

---

### Additional Examples

| Street | Food | Year | Example Output |
|---|---|---|---|
| `Honda` | `Sushi` | `2003` | `H0n#d@$u$h!20$03*4` |
| `Maple` | `Tacos` | `1987` | `M@p#l3T@c0$19$87!2` |
| `Church` | `Mango` | `2011` | `Chu#rchM@ng020$11%9` |

_(Entropy tail varies per run — the examples above illustrate the deterministic core.)_

---

## Encryption & Storage Architecture

```
Master Password (runtime only, never stored)
        │
        ▼
  PBKDF2-HMAC-SHA256
  480,000 iterations
  + 16-byte random salt  ←── ~/.passforge_salt.bin  (chmod 600)
        │
        ▼
  256-bit derived key
        │
        ▼
  Fernet (AES-128-CBC + HMAC-SHA256)
        │
        ▼
  Encrypted vault JSON  ──►  ~/.passforge_vault.enc  (chmod 600)
```

### Vault JSON structure (before encryption)

```json
{
  "GitHub": {
    "password": "B@k#erP!zza19$95^7",
    "created_at": "2025-07-10T14:32:05",
    "strength": "[EXCELLENT]"
  },
  "Gmail": {
    "password": "M@p#l3T@c0$19$87!2",
    "created_at": "2025-07-10T14:35:18",
    "strength": "[STRONG]"
  }
}
```

This JSON is UTF-8 encoded, Fernet-encrypted, and written as opaque binary. What is stored on disk looks like:

```
gAAAAABn... (base64-encoded ciphertext, ~200+ bytes per entry)
```

### Why Fernet and not raw AES?

Fernet is an authenticated encryption scheme: it wraps AES-128-CBC encryption with an HMAC-SHA256 authentication tag. This means:

- **Confidentiality** — the ciphertext reveals nothing about the plaintext
- **Integrity** — any modification to the file (including the HMAC tag) causes `InvalidToken` to be raised, preventing silent data corruption or padding-oracle attacks
- **Simplicity** — no IV management, no padding decisions; the library handles everything correctly

### Why PBKDF2 at 480,000 iterations?

A naive implementation would hash the master password once with SHA-256 to get a key. An attacker with a GPU can compute billions of SHA-256 hashes per second.

PBKDF2 intentionally forces `iterations` hash operations per password guess. At 480,000 iterations:

- Attacker speed: ~1 billion SHA-256/sec on a high-end GPU
- PBKDF2 cost per guess: 480,000 operations
- Effective guess rate: ~2,000 master password guesses/sec (down from billions)
- A 12-character random master password: ~centuries to brute-force

480,000 is the [OWASP 2024 recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) for PBKDF2-HMAC-SHA256.

---

## Security Considerations

### What PassForge protects against

| Threat | Mitigation |
|---|---|
| Vault file stolen from disk | AES-256 encryption — useless without master password |
| Master password brute-force | PBKDF2 at 480,000 iterations makes each guess ~480K× more expensive |
| Rainbow tables against master password | Unique 16-byte random salt per install |
| Silent vault corruption | Authenticated encryption (HMAC); any modification raises `InvalidToken` |
| Write-time crash corruption | Atomic write: old vault replaced only after new file is fully written |
| Shoulder-surfing via "logged in" session | Re-authentication required before any password is revealed |
| Trivially guessing password from known answers | Non-deterministic entropy tail appended by CSPRNG |

### Honest limitations

- **Single point of failure:** If you forget the master password, the vault is unrecoverable. There is no "forgot password" path by design.
- **Partial derivability:** The deterministic core of the password (stages 1–5) can be re-derived from your three answers. The entropy tail (stage 6) cannot. The vault copy is always authoritative.
- **Physical access:** If an attacker has persistent access to your unlocked machine and can intercept terminal I/O, no software vault can fully protect you.
- **Master password strength:** The entire system's security rests on the strength of your master password. Use at least 12 characters mixing words, numbers, and symbols.
- **No clipboard integration:** Passwords are printed to the terminal. Be aware of shoulder-surfing and terminal history.

### Files to back up

```
~/.passforge_vault.enc    ← your encrypted passwords
~/.passforge_salt.bin     ← the KDF salt (required to decrypt the vault)
```

Back up both files. Store them in separate locations (e.g. one on an encrypted USB drive, one in an encrypted cloud folder). They are only dangerous together, and only to someone who also knows the master password.

---

## Code Structure

```
passforge.py
│
├── CONFIGURATION
│   ├── VAULT_FILE / SALT_FILE paths
│   ├── KDF_ITER = 480,000
│   ├── LEET_MAP          (character substitution table)
│   └── SPECIALS_POOL     (special characters for interleaving and tail)
│
├── PART 1 — Key Derivation
│   ├── _load_or_create_salt()     → bytes
│   └── derive_fernet_key()        → Fernet instance
│
├── PART 2 — Vault I/O
│   ├── vault_read()               → dict  (decrypt + parse)
│   └── vault_write()              → None  (atomic encrypt + write)
│
├── PART 3 — Password Generation Algorithm
│   ├── _camel_word()              → str
│   ├── _selective_leet()          → str
│   ├── _interleave_special()      → str
│   ├── _year_transform()          → str
│   ├── _add_entropy_tail()        → str
│   └── generate_password()        → str  (orchestrates stages 1–7)
│
├── PART 4 — Strength Scorer
│   └── score_password()           → (int, str)
│
└── PART 5 — CLI Interface
    ├── prompt_master_password()
    ├── ask_questions()
    ├── menu_generate()
    ├── menu_list()
    ├── menu_retrieve()
    ├── menu_delete()
    └── main()
```

---

## Customisation

### Changing the PBKDF2 iteration count

Edit the constant at the top of the file:

```python
KDF_ITER = 480_000   # increase for more security, decrease for faster unlock
```

> **Warning:** Changing this after vault creation means the master password will derive a different key, and the vault will be unreadable. Change this only on a fresh install or after exporting/re-importing all passwords.

### Changing the vault location

```python
VAULT_FILE = Path.home() / ".passforge_vault.enc"   # change to any path
SALT_FILE  = Path.home() / ".passforge_salt.bin"
```

### Adding or changing the questions

```python
QUESTIONS = [
    ("street",  "  What street did you grow up on? "),
    ("food",    "  What is your all-time favourite food? "),
    ("year",    "  What is a meaningful year for you? "),
]
```

Replace any of the three tuples. The key (`"street"`, `"food"`, `"year"`) is used internally by `generate_password()` — if you rename them, update the references in that function too.

### Changing the leet map

```python
LEET_MAP = {
    'a': '@',  # change '@' to any character you prefer
    ...
}
```

---

## FAQ

**Q: What happens if I run PassForge on a new machine?**
A: Copy both `~/.passforge_vault.enc` and `~/.passforge_salt.bin` to the same paths on the new machine. The vault will open with the same master password.

**Q: Can I re-derive my password without the vault?**
A: You can re-derive the deterministic core (stages 1–5) by running PassForge with the same answers. The entropy tail (2 random chars at the end) will differ. If you need the exact password, you need the vault.

**Q: Is the vault safe to store in cloud backup (iCloud, Google Drive, Dropbox)?**
A: Yes. The vault is opaque ciphertext. Without the master password and the salt file, it is unreadable. The salt file should ideally be stored separately.

**Q: Why not use a well-known password manager like 1Password or Bitwarden?**
A: PassForge is for users who want zero cloud dependency, full code transparency, and to understand exactly what encrypts their passwords. 1Password and Bitwarden are excellent for most people. PassForge is for the security-conscious developer who wants to own the stack.

**Q: What Python version is required?**
A: Python 3.8 or higher. The walrus operator and `secrets` module (both used here) require 3.8+. Tested on 3.10 and 3.12.

**Q: Can multiple users share a vault?**
A: No. The vault is designed for a single user with a single master password. For shared credentials, consider a secrets manager with role-based access.

---

## Roadmap

- [ ] `--export` flag to dump vault as encrypted JSON backup
- [ ] `--import` flag to restore from backup
- [ ] Optional clipboard copy (with auto-clear after 30 seconds)
- [ ] Password rotation reminder (age-based warning in `menu_list`)
- [ ] Argon2id KDF option (more memory-hard than PBKDF2)
- [ ] GUI wrapper (Tkinter or web-based local server)
- [ ] Unit tests for the generation algorithm

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

Please ensure any changes to the encryption or KDF logic are accompanied by a security rationale in the PR description.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Python `cryptography` library](https://cryptography.io/) — the only dependency
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — KDF iteration guidance
- Inspired by the philosophy that **security and memorability are not opposites**

---

*PassForge — because your passwords should outlast your memory, not replace it.*
