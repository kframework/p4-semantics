Taken from https://github.com/usi-systems/p4xos-public/tree/26b48e0721fee7b3cddfa5c3335936b4f5c86ec7


Changes:
- Commented out checksum calculation (did not necessarily need to)
- Replaced `paxos.inst` in `register_read` and `register_write` to 0, since register index need to be a `VAL` according to the language specification.
- Added the assertion