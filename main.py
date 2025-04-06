import os
import time
import hashlib
import typing as T
from multiprocessing import Pool

def get_crypto_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(expected_crypto_hash: str, possible_password: str) -> bool:
    actual_crypto_hash = get_crypto_hash(possible_password)
    return expected_crypto_hash == actual_crypto_hash

def get_combinations(length: int, min_number: int, max_number: int) -> T.Iterator[str]:
    for i in range(min_number, max_number + 1):
        yield str(i).zfill(length)

ChunkRange = T.Tuple[int, int]

def get_chunks(num_chunks: int, length: int) -> T.Iterator[ChunkRange]:
    max_number = int(10**length - 1)
    chunk_size = (max_number + 1) // num_chunks

    for i in range(num_chunks):
        start = i * chunk_size
        end = ((i + 1) * chunk_size - 1) if i < num_chunks - 1 else max_number
        yield (start, end)

def crack_chunk(crypto_hash: str, length: int, chunk_start: int, chunk_end: int) -> T.Optional[str]:
    print(f"Processing range {chunk_start} to {chunk_end}")
    for combination in get_combinations(length, chunk_start, chunk_end):
        if check_password(crypto_hash, combination):
            return combination
    return None

def crack_password(crypto_hash: str, length: int) -> None:
    print("Starting brute-force password cracking")
    num_cores = os.cpu_count() or 4
    print(f"Using {num_cores} CPU cores")
    
    start_time = time.perf_counter()

    with Pool(processes=num_cores) as pool:
        arguments = (
            (crypto_hash, length, start, end)
            for start, end in get_chunks(num_cores, length)
        )
        results = pool.starmap(crack_chunk, arguments)

    result = next((r for r in results if r), None)

    if result:
        print(f"✅ PASSWORD CRACKED: {result}")
    else:
        print("❌ Password not found in given range.")

    duration = time.perf_counter() - start_time
    print(f"⏱️ Time taken: {duration:.2f} seconds")

if __name__ == "__main__":
    password = "11221974"
    crypto_hash = get_crypto_hash(password)  # hash of "0420"
    length = 8
    crack_password(crypto_hash, length)
