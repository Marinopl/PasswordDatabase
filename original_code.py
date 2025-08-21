import string
import secrets

SPECIALS = "!@#$%&*/?"

def generate_secure_token(length):

    if length < 10:
        raise ValueError("Password length should be at least 10 characters.")

    alphabet = string.ascii_letters + string.digits + SPECIALS

    return ''.join(secrets.choice(alphabet) for _ in range(length))

def duplicate_subs(pw: str) -> str:
    """Replace duplicate characters in the password with unique characters."""

    alphabet = set(string.ascii_letters + string.digits + SPECIALS)
    pw_list = list(pw)

    first_idx = {}
    duplicate_idx = []

    for i, ch in enumerate(pw_list):
        if ch in first_idx:
            duplicate_idx.append(i)
        else:
            first_idx[ch] = i

    used = set(pw_list)

    for i in duplicate_idx:
        candidates = list(alphabet - used)
        new_char = secrets.choice(candidates)
        used.add(new_char)
        pw_list[i] = new_char

    return ''.join(pw_list)

def shuffle(pw: str) -> str:
    """Shuffle the characters in the password."""
    pw_list = list(pw)
    secrets.SystemRandom().shuffle(pw_list)
    return ''.join(pw_list)

def ensure_policy(pw: str) -> bool:
    return (
        any(c.islower() for c in pw) and
        any(c.isupper() for c in pw) and
        any(c.isdigit() for c in pw) and
        any(c in SPECIALS for c in pw)
    )

def generate_password(length: int, unique: bool, max_tries: int = 10000) -> str:
    
    for _ in range(max_tries):
        pw = generate_secure_token(length)
        if not ensure_policy(pw):
            continue

        if unique:
            pw = duplicate_subs(pw)

        return pw
    
    raise ValueError("Failed to generate a valid password after maximum attempts.")

if __name__ == "__main__":
    password = generate_password(length=12, unique=True)
    print(f"Generated password: {password}")
    