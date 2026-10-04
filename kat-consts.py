# kat-consts.py — Known-Answer Test for the batch-4 crypto constant generators.
#
# Cuts the block between "# ==== BATCH4-CONSTS-BEGIN ====" and "# ==== BATCH4-CONSTS-END ===="
# out of scripts/DecompileBridge.py and executes it OUTSIDE Ghidra (it is pure Python by design),
# then asserts every table against published values.
#
#   py -3.13 kat-consts.py
#
# Why this exists: a hand-copied 256-byte S-box or a 64-entry K table is wrong silently — a
# signature with one wrong byte simply never matches, so the tool reports "nothing found" and
# nobody notices. These byte-level KATs are the only thing standing between that and a green run.

import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'scripts', 'DecompileBridge.py')

BEGIN = '# ==== BATCH4-CONSTS-BEGIN ===='
END = '# ==== BATCH4-CONSTS-END ===='

checks = []
failures = []


def eq(label, got, want):
    checks.append(label)
    if got != want:
        failures.append('%s: got %r, want %r' % (label, got, want))


def truthy(label, got):
    checks.append(label)
    if not got:
        failures.append('%s: falsy (%r)' % (label, got))


def hexs(bs):
    return ''.join('%02X' % (int(b) & 0xFF) for b in bs)


def main():
    text = io.open(SRC, encoding='utf-8').read()
    if BEGIN not in text or END not in text:
        print('KAT FAIL: markers not found in %s' % SRC)
        return 1
    block = text[text.index(BEGIN):text.index(END)]
    ns = {}
    exec(compile(block, 'batch4-consts', 'exec'), ns)

    iroot = ns['_iroot']
    primes = ns['_primes']
    words_be = ns['_words_be']
    words_le = ns['_words_le']
    sbox = ns['_aes_sbox']()
    inv = ns['_aes_inv_sbox'](sbox)
    crc = ns['_crc_table'](0xEDB88320)
    crcc = ns['_crc_table'](0x82F63B78)
    tt = ns['_md5_t']()
    rc = ns['_keccak_rc']()
    sigs = ns['_crypto_signatures']()

    # ---- integer helpers
    eq('iroot(27,3)', iroot(27, 3), 3)
    eq('iroot(26,3)', iroot(26, 3), 2)
    eq('iroot(10**18,2)', iroot(10 ** 18, 2), 10 ** 9)
    eq('iroot(0,5)', iroot(0, 5), 0)
    eq('primes(8)', primes(8), [2, 3, 5, 7, 11, 13, 17, 19])
    eq('primes(25)[24]', primes(25)[24], 97)

    # ---- byte order helpers
    eq('words_be([0x11223344],4)', list(words_be([0x11223344], 4)), [0x11, 0x22, 0x33, 0x44])
    eq('words_le([0x11223344],4)', list(words_le([0x11223344], 4)), [0x44, 0x33, 0x22, 0x11])
    eq('words_be([1],8)', list(words_be([1], 8)), [0] * 7 + [1])

    # ---- AES (FIPS-197)
    eq('aes sbox len', len(sbox), 256)
    eq('aes sbox[0x00]', sbox[0x00], 0x63)
    eq('aes sbox[0x01]', sbox[0x01], 0x7C)
    eq('aes sbox[0x53]', sbox[0x53], 0xED)
    eq('aes sbox[0xFF]', sbox[0xFF], 0x16)
    eq('aes sbox[0x10]', sbox[0x10], 0xCA)
    truthy('aes inv(sbox) identity', all(inv[sbox[i]] == i for i in range(256)))

    # ---- CRC tables
    eq('crc32 table len', len(crc), 256)
    eq('crc32 table[0]', crc[0], 0)
    eq('crc32 table[1]', crc[1], 0x77073096)
    eq('crc32 table[2]', crc[2], 0xEE0E612C)
    eq('crc32 table[255]', crc[255], 0x2D02EF8D)
    eq('crc32c table[1]', crcc[1], 0xF26B8303)

    # ---- MD5
    eq('md5 T len', len(tt), 64)
    eq('md5 T[0]', tt[0], 0xD76AA478)
    eq('md5 T[1]', tt[1], 0xE8C7B756)
    eq('md5 T[2]', tt[2], 0x242070DB)
    eq('md5 T[63]', tt[63], 0xEB86D391)

    # ---- SHA-1 / SHA-256 (FIPS-180-4)
    sha1h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    eq('sha1 init be', hexs(words_be(sha1h, 4)), '67452301EFCDAB8998BADCFE10325476C3D2E1F0')
    h256 = ns['_frac_bits'](lambda p: iroot(p << 64, 2), 8, 32)
    eq('sha256 h0', h256[0], 0x6A09E667)
    eq('sha256 h1', h256[1], 0xBB67AE85)
    eq('sha256 h7', h256[7], 0x5BE0CD19)
    k256 = ns['_frac_bits'](lambda p: iroot(p << 96, 3), 64, 32)
    eq('sha256 k len', len(k256), 64)
    eq('sha256 k0', k256[0], 0x428A2F98)
    eq('sha256 k1', k256[1], 0x71374491)
    eq('sha256 k63', k256[63], 0xC67178F2)
    k512 = ns['_frac_bits'](lambda p: iroot(p << 192, 3), 80, 64)
    eq('sha512 k len', len(k512), 80)
    eq('sha512 k0', k512[0], 0x428A2F98D728AE22)
    eq('sha512 k1', k512[1], 0x7137449123EF65CD)
    eq('sha512 k79', k512[79], 0x6C44198C4A475817)
    h512 = ns['_frac_bits'](lambda p: iroot(p << 128, 2), 8, 64)
    eq('sha512 h0', h512[0], 0x6A09E667F3BCC908)
    eq('sha512 h1', h512[1], 0xBB67AE8584CAA73B)

    # ---- Keccak / SHA-3 round constants
    eq('keccak rc len', len(rc), 24)
    eq('keccak rc[0]', rc[0], 0x0000000000000001)
    eq('keccak rc[1]', rc[1], 0x0000000000008082)
    eq('keccak rc[2]', rc[2], 0x800000000000808A)
    eq('keccak rc[23]', rc[23], 0x8000000080008008)

    # ---- embedded constants inside the signature table
    by_name = dict((s[0], s) for s in sigs)
    eq('chacha 32 constant',
       ''.join(chr(b) for b in by_name['ChaCha/Salsa "expand 32-byte k"'][2]),
       'expand 32-byte k')
    eq('chacha 16 constant',
       ''.join(chr(b) for b in by_name['ChaCha/Salsa "expand 16-byte k"'][2]),
       'expand 16-byte k')
    eq('base64 alphabet',
       ''.join(chr(b) for b in by_name['Base64 alphabet'][2]),
       'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
    eq('base64url alphabet',
       ''.join(chr(b) for b in by_name['Base64 URL-safe alphabet'][2]),
       'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
    eq('blowfish P-array', hexs(by_name['Blowfish P-array'][2]), '243F6A8885A308D3')
    eq('curve25519 prime',
       hexs(by_name['Curve25519 prime'][2]),
       '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED')
    eq('secp256k1 prime',
       hexs(by_name['secp256k1 prime'][2]),
       'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F')
    eq('p256 prime',
       hexs(by_name['P-256 prime'][2]),
       'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF')
    eq('sha256 init signature (be)',
       hexs(by_name['SHA-256 init'][2]),
       '6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19')

    # ---- table hygiene: every signature is a non-empty byte list
    truthy('signature count >= 25', len(sigs) >= 25)
    bad = []
    for name, algo, body, note in sigs:
        if not body:
            bad.append(name + ' (empty)')
            continue
        for b in body:
            v = int(b)
            if v < 0 or v > 255:
                bad.append('%s (byte %r out of range)' % (name, b))
                break
        if not algo or not note:
            bad.append(name + ' (missing algorithm/note)')
    eq('all signatures well formed', bad, [])

    # ---- the three full 256-entry tables must actually be 256 bytes
    eq('aes sbox signature length', len(by_name['AES S-box'][2]), 256)
    eq('aes inv sbox signature length', len(by_name['AES inverse S-box'][2]), 256)
    eq('crc32 full signature length', len(by_name['CRC32 table (full)'][2]), 1024)
    eq('md5 T full signature length', len(by_name['MD5 T table (full)'][2]), 256)
    eq('sha256 K full signature length', len(by_name['SHA-256 K (full)'][2]), 256)

    if failures:
        print('KAT FAILED — %d/%d checks failed' % (len(failures), len(checks)))
        for f in failures:
            print('  FAIL ' + f)
        return 1
    print('KAT OK — %d checks passed, %d signatures verified' % (len(checks), len(sigs)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
