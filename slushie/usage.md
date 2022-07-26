# Using Slushie

### Note
At the point of writing, Slushie is not even in alpha.
It does not do any ZKP verification, so consider this to be just a skeleton.

## Usage

Use as a normal ink!-based contract.
Build & deploy to `polkadot.js.org/apps` while using local `substrate-contracts-node`, or
in some testnet that supports `pallet-contracts`.

Slushie is a mixer, so it means the two most important actions are:
1) Deposit funds from your account to Slushie
2) Withdraw funds from Slushie to a different account

For this, we have two contract messages: `deposit` and `withdraw`.
Right now, `deposit` only takes the `commitment` as the input,
while also receiving some transferred value (that one will be
able to withdraw later, knowing the randomness and the nullifier hash).
`withdraw` takes a `nullifier_hash` and `root` (meaning
the merkle tree root) as inputs. The Merkle Tree root is used to determine
the point in time when were the funds deposited, and by knowing the
correct values (nullifier hash, randomness, root, and later the Proof),
anyone can withdraw the amount of funds that someone deposited using
those values.