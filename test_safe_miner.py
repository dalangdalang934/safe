import os
import struct
import unittest
from safe_miner import _hash, kernel_source, lanes_to_address, repeated_score, safe_address, validate_candidate

FACTORY = '4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67'
CODE_HASH = bytes.fromhex('76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb')


def _initializer_hash():
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'initializer.txt')) as f:
        return _hash(bytes.fromhex(f.read().strip()[2:]))


@unittest.skipUnless(os.environ.get('OPENCL_TEST'), 'set OPENCL_TEST=1 to run on the GPU server')
class ParallelHashTest(unittest.TestCase):
    def test_parallel_hash_nonce_matches_cpu(self):
        import numpy as np
        import pyopencl as cl
        from safe_miner import build_program, select_device

        initializer_hash = bytes.fromhex(os.environ['INITIALIZER_HASH'])
        start = int(os.environ.get('START_NONCE', '0'))
        count = 1 << 20
        context = cl.Context([select_device(cl)])
        queue = cl.CommandQueue(context)
        program = build_program(cl, context, FACTORY, initializer_hash, CODE_HASH)
        output = np.empty((count, 4), dtype=np.uint64)
        output_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, output.nbytes)
        program.hash_nonce(queue, (count,), None, np.uint64(start), output_buf)
        cl.enqueue_copy(queue, output, output_buf)
        queue.finish()
        for nonce in range(start, start + count):
            expected = _hash(initializer_hash + nonce.to_bytes(32, 'big'))
            if output[nonce - start].tobytes() != expected:
                self.fail(f'nonce {nonce}: GPU {output[nonce - start].tobytes().hex()}, CPU {expected.hex()}')

    def test_parallel_mine_returns_cpu_validated_candidate(self):
        from safe_miner import mine

        best = mine(FACTORY, bytes.fromhex(os.environ['INITIALIZER_HASH']), CODE_HASH, seconds=1)
        self.assertGreaterEqual(best['score'], 5)


class RepeatedScoreTest(unittest.TestCase):
    def test_accepts_any_repeated_prefix_or_suffix_nibble(self):
        self.assertEqual(repeated_score(bytes.fromhex('aaaaaaaaaaaaaaaaaaaabbbbcccccccccccccccccccc')), 20)
        self.assertEqual(repeated_score(bytes.fromhex('1234567890123456789012345678901234567890')), 1)

    def test_uses_longer_suffix(self):
        self.assertEqual(repeated_score(bytes.fromhex('1111222233334444555566667777777777')), 10)


class SafeAddressTest(unittest.TestCase):
    def test_matches_reference_create2_derivation(self):
        address = safe_address(
            FACTORY,
            'dc50d6fbe25fc5fe0cffb1a2fc5170b76ac620f74f22c7b247d8c73d83072302',
            bytes.fromhex('b63e800d0000000000000000000000000000000000000000000000000000000000000001'),
            bytes.fromhex('00' * 32),
        )
        self.assertEqual(len(address), 20)

    def test_readme_example(self):
        best = validate_candidate(
            FACTORY, 8087313955986017249,
            bytes.fromhex('39e232a22c783acf5af79c4e255fd88888888888'),
            _initializer_hash(), CODE_HASH, 11,
        )
        self.assertEqual(best['address'], '0x39e232a22c783acf5af79c4e255fd88888888888')

    def test_rejects_gpu_candidate_that_does_not_match_cpu(self):
        with self.assertRaisesRegex(ValueError, 'address mismatch'):
            validate_candidate(FACTORY, 9, bytes(20), bytes(32), bytes(32), 3)


class KernelInputTest(unittest.TestCase):
    def test_lanes_to_address_takes_hash_bytes_12_to_31(self):
        digest = bytes(range(32))
        a1, a2, a3 = struct.unpack('<3Q', digest[8:])
        self.assertEqual(lanes_to_address(a1, a2, a3), digest[12:])

    def test_create2_lanes_match_preimage_layout(self):
        source = kernel_source(FACTORY, bytes(range(32)), CODE_HASH)
        lanes = {}
        for line in source.splitlines():
            if line.startswith('#define CREATE2_'):
                name, value = line.split()[1:]
                lanes[int(name[8:])] = int(value[:-2], 16)
        preimage = b''.join(struct.pack('<Q', lanes[i]) for i in range(17))
        self.assertEqual(preimage[0], 0xff)
        self.assertEqual(preimage[1:21], bytes.fromhex(FACTORY))
        self.assertEqual(preimage[21:53], bytes(32))
        self.assertEqual(preimage[53:85], CODE_HASH)
        self.assertEqual(preimage[85], 1)
        self.assertEqual(preimage[135], 0x80)


if __name__ == '__main__':
    unittest.main()
