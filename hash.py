import hashlib

sha256_hash = hashlib.sha256()

filename = 'MALWR/sample_vg655_25th.exe'

with open(filename,"rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096),b""):
        sha256_hash.update(byte_block)
    print(sha256_hash.hexdigest())

#Hash obtenido
##ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa