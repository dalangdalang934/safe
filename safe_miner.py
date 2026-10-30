from Crypto.Hash import keccak


def _hash(data):
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def repeated_score(address):
    digits = address.hex()
    prefix = 1
    while prefix < 40 and digits[prefix] == digits[0]:
        prefix += 1
    suffix = 1
    while suffix < 40 and digits[-1 - suffix] == digits[-1]:
        suffix += 1
    return max(prefix, suffix)


def safe_address(factory, salt_nonce, initializer_hash, proxy_creation_code_hash):
    nonce = int(salt_nonce, 16).to_bytes(32, 'big')
    salt = _hash(initializer_hash + nonce)
    message = b'\xff' + bytes.fromhex(factory) + salt + proxy_creation_code_hash
    return _hash(message)[12:]


def validate_candidate(factory, nonce, salt, address, initializer_hash, proxy_creation_code_hash, score):
    nonce_bytes = nonce.to_bytes(32, 'big')
    if salt != _hash(initializer_hash + nonce_bytes):
        raise ValueError('salt mismatch')
    expected = safe_address(factory, hex(nonce), initializer_hash, proxy_creation_code_hash)
    if address != expected:
        raise ValueError(f'address mismatch: GPU {address.hex()}, CPU {expected.hex()}')
    if repeated_score(expected) != score:
        raise ValueError('score mismatch')
    return {'score': score, 'saltNonce': str(nonce), 'address': '0x' + expected.hex()}


def mine(factory, initializer_hash, proxy_creation_code_hash, seconds=15):
    import json
    import time
    import numpy as np
    import pyopencl as cl

    platform = next(p for p in cl.get_platforms() if 'NVIDIA' in p.name)
    device = platform.get_devices()[0]
    context = cl.Context([device])
    queue = cl.CommandQueue(context)
    with open('safe_miner.cl') as f:
        program = cl.Program(context, f.read()).build()
    init_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=initializer_hash)
    factory_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=bytes.fromhex(factory))
    code_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=proxy_creation_code_hash)
    score_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array([0], dtype=np.uint32))
    nonce_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array([0], dtype=np.uint64))
    address_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE, 20)
    salt_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE, 32)
    lock_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=np.array([0], dtype=np.uint32))
    kernel = cl.Kernel(program, 'mine')
    import secrets
    work_size = 1 << 24
    base = secrets.randbits(63)
    attempts = 0
    start = time.monotonic()
    best = {'score': 0}
    while time.monotonic() - start < seconds:
        kernel(queue, (work_size,), None, init_buf, factory_buf, code_buf, np.uint64(base), score_buf, nonce_buf, address_buf, lock_buf, salt_buf)
        base += work_size
        attempts += work_size
        score = np.empty(1, dtype=np.uint32)
        nonce = np.empty(1, dtype=np.uint64)
        address = bytearray(20)
        salt = bytearray(32)
        cl.enqueue_copy(queue, score, score_buf)
        cl.enqueue_copy(queue, nonce, nonce_buf)
        cl.enqueue_copy(queue, address, address_buf)
        cl.enqueue_copy(queue, salt, salt_buf)
        queue.finish()
        if score[0] > best['score']:
            best = validate_candidate(factory, int(nonce[0]), bytes(salt), bytes(address), initializer_hash, proxy_creation_code_hash, int(score[0]))
            with open('best-safe.json', 'w') as f:
                json.dump(best, f, indent=2)
            print(json.dumps(best), flush=True)
        elapsed = time.monotonic() - start
        print(f'{attempts / elapsed / 1e6:.1f} MH/s; best={best}', flush=True)
    return best


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('factory')
    parser.add_argument('initializer_hash')
    parser.add_argument('proxy_creation_code_hash')
    parser.add_argument('--seconds', type=float, default=15)
    args = parser.parse_args()
    mine(args.factory, bytes.fromhex(args.initializer_hash), bytes.fromhex(args.proxy_creation_code_hash), args.seconds)
