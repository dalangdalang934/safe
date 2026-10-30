import json
import os
import struct

from Crypto.Hash import keccak

KERNEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'safe_miner.cl')
CANDIDATE_CAP = 1024
FOUND_WORDS = 5


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


def validate_candidate(factory, nonce, address, initializer_hash, proxy_creation_code_hash, score):
    expected = safe_address(factory, hex(nonce), initializer_hash, proxy_creation_code_hash)
    if address != expected:
        raise ValueError(f'address mismatch: GPU {address.hex()}, CPU {expected.hex()}')
    if repeated_score(expected) != score:
        raise ValueError('score mismatch')
    return {'score': score, 'saltNonce': str(nonce), 'address': '0x' + expected.hex()}


def kernel_source(factory, initializer_hash, proxy_creation_code_hash):
    """Kernel source with the constant Keccak input lanes baked in as #defines."""
    preimage = bytearray(136)
    preimage[0] = 0xff
    preimage[1:21] = bytes.fromhex(factory)
    preimage[53:85] = proxy_creation_code_hash
    preimage[85] = 0x01
    preimage[135] = 0x80
    defines = [f'#define INIT{i} 0x{v:016x}UL' for i, v in enumerate(struct.unpack('<4Q', initializer_hash))]
    defines += [f'#define CREATE2_{i} 0x{v:016x}UL' for i, v in enumerate(struct.unpack('<17Q', preimage))]
    defines.append(f'#define CANDIDATE_CAP {CANDIDATE_CAP}u')
    with open(KERNEL_PATH) as f:
        return '\n'.join(defines) + '\n' + f.read()


def lanes_to_address(a1, a2, a3):
    return struct.pack('<QQQ', a1, a2, a3)[4:]


def select_device(cl, index=None):
    devices = [d for p in cl.get_platforms() for d in p.get_devices()]
    if not devices:
        raise RuntimeError('no OpenCL devices found')
    if index is not None:
        return devices[index]
    gpus = [d for d in devices if d.type & cl.device_type.GPU]
    nvidia = [d for d in gpus if 'NVIDIA' in d.platform.name]
    return (nvidia or gpus or devices)[0]


def build_program(cl, context, factory, initializer_hash, proxy_creation_code_hash):
    source = kernel_source(factory, initializer_hash, proxy_creation_code_hash)
    return cl.Program(context, source).build()


def _write_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def mine(factory, initializer_hash, proxy_creation_code_hash, seconds=15, work_size=1 << 26,
         min_score=5, device_index=None, output='best-safe.json'):
    import secrets
    import time
    import numpy as np
    import pyopencl as cl

    device = select_device(cl, device_index)
    print(f'device: {device.name} ({device.platform.name})', flush=True)
    context = cl.Context([device])
    queue = cl.CommandQueue(context)
    program = build_program(cl, context, factory, initializer_hash, proxy_creation_code_hash)
    zero = np.zeros(1, dtype=np.uint32)
    count = np.zeros(1, dtype=np.uint32)
    found = np.empty(CANDIDATE_CAP * FOUND_WORDS, dtype=np.uint64)
    count_buf = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=zero)
    found_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, found.nbytes)
    kernel = cl.Kernel(program, 'mine')
    kernel.set_args(np.uint64(0), np.uint32(0), count_buf, found_buf)

    base = secrets.randbits(63)
    attempts = 0
    start = last_report = time.monotonic()
    best = {'score': 0}
    try:
        while seconds <= 0 or time.monotonic() - start < seconds:
            kernel.set_arg(0, np.uint64(base))
            kernel.set_arg(1, np.uint32(max(min_score, best['score'] + 1)))
            cl.enqueue_nd_range_kernel(queue, kernel, (work_size,), None)
            cl.enqueue_copy(queue, count, count_buf)
            base += work_size
            attempts += work_size
            if count[0]:
                n = min(int(count[0]), CANDIDATE_CAP)
                cl.enqueue_copy(queue, found[:n * FOUND_WORDS], found_buf)
                cl.enqueue_copy(queue, count_buf, zero)
                rows = found[:n * FOUND_WORDS].reshape(n, FOUND_WORDS)
                top = rows[rows[:, 4].argmax()]
                if int(top[4]) > best['score']:
                    address = lanes_to_address(int(top[1]), int(top[2]), int(top[3]))
                    best = validate_candidate(factory, int(top[0]), address, initializer_hash,
                                              proxy_creation_code_hash, int(top[4]))
                    _write_json(output, best)
                    print(json.dumps(best), flush=True)
            now = time.monotonic()
            if now - last_report >= 5:
                last_report = now
                print(f'{attempts / (now - start) / 1e6:.1f} MH/s; best={best}', flush=True)
    except KeyboardInterrupt:
        pass
    queue.finish()
    elapsed = time.monotonic() - start
    print(f'{attempts} attempts in {elapsed:.1f}s, {attempts / elapsed / 1e6:.1f} MH/s; best={best}', flush=True)
    return best


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('factory')
    parser.add_argument('initializer_hash')
    parser.add_argument('proxy_creation_code_hash')
    parser.add_argument('--seconds', type=float, default=15, help='run time; 0 runs until Ctrl+C')
    parser.add_argument('--work-size', type=int, default=1 << 26, help='nonces per kernel launch')
    parser.add_argument('--min-score', type=int, default=5)
    parser.add_argument('--device', type=int, help='index into all OpenCL devices across platforms')
    parser.add_argument('--output', default='best-safe.json')
    args = parser.parse_args()
    mine(args.factory, bytes.fromhex(args.initializer_hash), bytes.fromhex(args.proxy_creation_code_hash),
         args.seconds, args.work_size, args.min_score, args.device, args.output)
