import hashlib
import itertools
import re
from multiprocessing import Pool, cpu_count
import sys

# import crypt
import bcrypt
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import multiprocessing

# --- HASHING ALGORITHMS ---


def md5(s: bytes, salt=None) -> str:
    return hashlib.md5(s).hexdigest()


def sha1(s: bytes, salt=None) -> str:
    return hashlib.sha1(s).hexdigest()


def sha224(s: bytes, salt=None) -> str:
    return hashlib.sha224(s).hexdigest()


def sha256(s: bytes, salt=None) -> str:
    return hashlib.sha256(s).hexdigest()


def sha384(s: bytes, salt=None) -> str:
    return hashlib.sha384(s).hexdigest()


def sha512(s: bytes, salt=None) -> str:
    return hashlib.sha512(s).hexdigest()


def scrypt(s: bytes, salt=None) -> str:
    if salt is None:
        salt = b'salt'
    return hashlib.scrypt(s, salt=salt, n=2**14, r=8, p=1).hex()


def bcrypt_hash(s: bytes, salt: str) -> str:
    return bcrypt.hashpw(s, salt.encode()).decode()


def argon2_hash(s: bytes, salt: str) -> str:
    ph = PasswordHasher()
    try:
        # This generates its own salt, but we use verification instead
        return ph.hash(s.decode())
    except Exception:
        return ""


# def crypt_hash(s: bytes, salt: str) -> str:
#     return crypt.crypt(s.decode(), salt)

# --- HASHING FUNCTION SELECTOR ---


def getHash(type):
    hash_map = {
        "md5": md5,
        "sha1": sha1,
        "sha224": sha224,
        "sha256": sha256,
        "sha384": sha384,
        "sha512": sha512,
        "scrypt": scrypt,
        "bcrypt": bcrypt_hash,
        "argon2": argon2_hash,
        # "crypt": crypt_hash,
    }
    return hash_map.get(type.lower(), None)

# --- SALT EXTRACTORS ---


def extract_bcrypt_salt(hash):
    return hash[:29] if hash.startswith("$2") else None


def extract_argon2_salt(hash):
    parts = hash.split('$')
    if len(parts) >= 6 and parts[1].startswith("argon2"):
        return "$".join(parts[:5]) + "$"
    return None


def extract_crypt_salt(hash):
    match = re.match(r"^\$[0-9a-zA-Z]+\$[^$]+", hash)
    return match.group(0) if match else None

# --- SALT MAP SELECTOR ---


def getSaltExtractor(hash_type):
    salt_map = {
        'bcrypt': extract_bcrypt_salt,
        'argon2': extract_argon2_salt,
        'crypt': extract_crypt_salt,
    }
    return salt_map.get(hash_type.lower(), None)

# --- PASSWORD CRACKER CLASS ---


class CPUCracker:
    def __init__(self, charset='abcdefghijklmnopqrstuvwxyz0123456789', max_length=5, batch_size=50000):
        self.charset = charset
        self.max_length = max_length
        self.batch_size = batch_size
        self.target_hash = None
        self.hash_func = None
        self.salt = None
        self.hash_type = None

    def init_worker(self, hash_func, target_hash, salt, hash_type):
        global global_hash_func, global_target_hash, global_salt, global_hash_type
        global_hash_func = hash_func
        global_target_hash = target_hash
        global_salt = salt
        global_hash_type = hash_type

    def worker(self, batch):
        for word in batch:
            word_str = ''.join(word)
            word_bytes = word_str.encode('utf-8')

            if global_hash_type in ['bcrypt', 'crypt']:
                result = global_hash_func(word_bytes, global_salt)
                if result == global_target_hash:
                    return word_str
            elif global_hash_type == 'argon2':
                try:
                    ph = PasswordHasher()
                    if ph.verify(global_target_hash, word_str):
                        return word_str
                except argon2_exceptions.VerifyMismatchError:
                    continue
                except Exception:
                    continue
            else:
                result = global_hash_func(word_bytes, global_salt)
                if result == global_target_hash:
                    return word_str
        return None

    def batched(self, it, size):
        batch = []
        for item in it:
            batch.append(item)
            if len(batch) == size:
                yield batch
                batch = []
        if batch:
            yield batch

    def crack(self, hash_type, target_hash):
        self.hash_type = hash_type
        self.target_hash = target_hash
        self.hash_func = getHash(hash_type)
        salt_extractor = getSaltExtractor(hash_type)
        self.salt = salt_extractor(target_hash) if salt_extractor else None

        if not self.hash_func:
            raise ValueError(f"Unsupported hash type: {hash_type}")

        for length in range(1, self.max_length + 1):
            generator = itertools.product(self.charset, repeat=length)
            pool = Pool(processes=cpu_count(), initializer=self.init_worker,
                        initargs=(self.hash_func, self.target_hash, self.salt, self.hash_type))

            try:
                for result in pool.imap_unordered(self.worker, self.batched(generator, self.batch_size)):
                    if result:
                        pool.terminate()
                        pool.join()
                        return result
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                print("\n[!] Interrupted by user.")
                sys.exit(1)

            pool.close()
            pool.join()
        return None

# --- MAIN EXECUTION ---

if __name__ == '__main__':
    multiprocessing.freeze_support()
    print("Usage example: <hash> <hash_type>", flush=True)
    print("Supported types: md5, sha1, sha224, sha256, sha384, sha512, scrypt, bcrypt, argon2, crypt", flush=True)
    print("To exit the program, type: exit", flush=True)
    
    cracker = CPUCracker()

    # while True:
    try:
        user_input = sys.stdin.readline().strip()
        print(user_input)
        if user_input.lower() == "exit":
            print("Exiting...")
            # break
            sys.exit()

        parts = user_input.split(maxsplit=1)
        if len(parts) != 2:
            print("Invalid format. Use: <hash> <hash_type>")
            # continue
            sys.exit()

        target_hash, hash_type = parts
        print(f"[*] Cracking {hash_type} hash: {target_hash}")
        result = cracker.crack(hash_type, target_hash)


        if result:
            print(f"[+] Password found: {result}")
        else:
            print("[-] Password not found.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        # break
        sys.exit()
