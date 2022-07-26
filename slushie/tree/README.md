# Merkle Tree with history

Merkle Tree with history implementation, which can use different hash algorithms and different history size. 

Merkle Tree methods:
- new – create Merkle Tree, using generics, return error if DEPTH is not correct
- get_last_root – return last computed root
- is_known_root(root) – check if provided root exist in history
- insert(leaf) – insert leaf in the Merkle Tree, return error if Merkle Tree is full 

## Available hash algorithms

- Blake2x256
- Poseidon

## Blake2x256

Blake hash implementation provided by [`ink_env`](https://crates.io/crates/ink_env). 

- Branches – Blake2x256 hash(32 bytes) of concatenated left and right subtrees. 
- Zero element – Blake2x256 hash of "slushie".

## Poseidon

[Poseidon](https://www.poseidon-hash.info/) is zero-knowledge friendly hash function, which uses up to 8x fewer constraints per message bit than Pedersen Hash. Poseidon hash implementation provided by [`dusk-poseidon`](https://crates.io/crates/dusk-poseidon). This implementation works with a group of points of the BLS12-381 elliptic curve, which is provided by [`dusk-bls12_381`](https://crates.io/crates/dusk-bls12_381). 

- Branches – Poseidon hash of left and right subtrees which is transformed to bytes (32 bytes). 
- Zero element – scalar from Blake2x256 hash of "slushie" transformed to bytes (32 bytes).