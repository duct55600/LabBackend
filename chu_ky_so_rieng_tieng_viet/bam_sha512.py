from Crypto.Hash import SHA512

def bam_hoa(du_lieu: bytes) -> bytes:
    return SHA512.new(du_lieu).digest()