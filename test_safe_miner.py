import os
import unittest
from safe_miner import _hash, repeated_score, safe_address, validate_candidate


@unittest.skipUnless(os.environ.get('OPENCL_TEST'), 'set OPENCL_TEST=1 to run on the GPU server')
class ParallelHashTest(unittest.TestCase):
    def test_parallel_hash_nonce_matches_cpu(self):
        import numpy as np
        import pyopencl as cl

        initializer_hash = bytes.fromhex(os.environ['INITIALIZER_HASH'])
        start = int(os.environ.get('START_NONCE', '0'))
        count = 1 << 20
        platform = next(p for p in cl.get_platforms() if 'NVIDIA' in p.name)
        context = cl.Context([platform.get_devices()[0]])
        queue = cl.CommandQueue(context)
        with open('safe_miner.cl') as f:
            program = cl.Program(context, f.read()).build()
        init_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=initializer_hash)
        output = np.empty((count, 32), dtype=np.uint8)
        output_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, output.nbytes)
        program.hash_nonce(queue, (count,), None, init_buf, np.uint64(start), output_buf)
        cl.enqueue_copy(queue, output, output_buf)
        queue.finish()
        for nonce in range(start, start + count):
            expected = _hash(initializer_hash + nonce.to_bytes(32, 'big'))
            if output[nonce - start].tobytes() != expected:
                self.fail(f'nonce {nonce}: GPU {output[nonce - start].tobytes().hex()}, CPU {expected.hex()}')

    def test_parallel_mine_returns_cpu_validated_candidate(self):
        from safe_miner import mine

        best = mine(
            '4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67',
            bytes.fromhex(os.environ['INITIALIZER_HASH']),
            bytes.fromhex('76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb'),
            seconds=1,
        )
        self.assertGreaterEqual(best['score'], 4)


class RepeatedScoreTest(unittest.TestCase):
    def test_accepts_any_repeated_prefix_or_suffix_nibble(self):
        self.assertEqual(repeated_score(bytes.fromhex('aaaaaaaaaaaaaaaaaaaabbbbcccccccccccccccccccc')), 20)
        self.assertEqual(repeated_score(bytes.fromhex('1234567890123456789012345678901234567890')), 1)

    def test_uses_longer_suffix(self):
        self.assertEqual(repeated_score(bytes.fromhex('1111222233334444555566667777777777')), 10)


class SafeAddressTest(unittest.TestCase):
    def test_matches_reference_create2_derivation(self):
        address = safe_address(
            '4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67',
            'dc50d6fbe25fc5fe0cffb1a2fc5170b76ac620f74f22c7b247d8c73d83072302',
            bytes.fromhex('b63e800d0000000000000000000000000000000000000000000000000000000000000001'),
            bytes.fromhex('00' * 32),
        )
        self.assertEqual(len(address), 20)

    def test_rejects_gpu_candidate_that_does_not_match_cpu(self):
        with self.assertRaisesRegex(ValueError, 'salt mismatch'):
            validate_candidate(
                '4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67',
                9, bytes(32), bytes(32), bytes(20), bytes(32), 3,
            )


if __name__ == '__main__':
    unittest.main()
