import hashlib
import itertools
from multiprocessing import Pool, cpu_count
import sys


def md5(s: bytes) -> str:
    return hashlib.md5(s).hexdigest()


def sha1(s: bytes) -> str:
    return hashlib.sha1(s).hexdigest()


def sha256(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def sha512(s: bytes) -> str:
    return hashlib.sha512(s).hexdigest()


def scrypt(s: bytes) -> str:
    return hashlib.scrypt(s, salt=b'salt', n=2**14, r=8, p=1).hex()


def getHash(type):
    hash_map = {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "sha512": sha512,
        "scrypt": scrypt,
    }
    return hash_map.get(type.lower(), None)


class CPUCracker:
    def __init__(self, charset='abcdefghijklmnopqrstuvwxyz0123456789', max_length=5, batch_size=50000):
        self.charset = charset
        self.max_length = max_length
        self.batch_size = batch_size
        self.target_hash = None
        self.hash_func = None

    def init_worker(self, hash_func, target_hash):
        global global_hash_func, global_target_hash
        global_hash_func = hash_func
        global_target_hash = target_hash

    def worker(self, batch):
        for word in batch:
            word_bytes = ''.join(word).encode('utf-8')
            if global_hash_func(word_bytes) == global_target_hash:
                return ''.join(word)
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
        self.target_hash = target_hash
        self.hash_func = getHash(hash_type)
        if self.hash_func is None:
            raise ValueError(f"Unsupported hash type: {hash_type}")

        for length in range(1, self.max_length + 1):
            generator = itertools.product(self.charset, repeat=length)
            pool = Pool(processes=cpu_count(), initializer=self.init_worker, initargs=(
                self.hash_func, self.target_hash))

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


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(1)

    hash_type = sys.argv[1]
    target_hash = sys.argv[2]

    cracker = CPUCracker()
    result = cracker.crack(hash_type, target_hash)

    if result:
        print(f"[+] Password found: {result}")
    else:
        print("[-] Password not found.")
