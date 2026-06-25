# bip-0039
Native Go implementation of Bitcoin's BIP-0039 specification with official test vectors validation.


## Credits & Wordlists License

This library includes all official multi-language wordlists from the Bitcoin BIP-0039 specification. 

The wordlists are available for the following languages:
* English, Japanese, Korean, Spanish, Chinese (Simplified & Traditional), French, Italian, Czech, Portuguese.

All wordlists are sourced directly from the [Official Bitcoin BIP-0039 Repository](https://github.com/bitcoin/bips/tree/master/bip-0039) and are released under the **CC0 (Public Domain)** license.


### Multi-language Support & Special Considerations
This library strictly follows the official language rules outlined in the BIP-0039 specification (such as Japanese ideographic space normalization and Spanish 4-character uniqueness).
See [WORDLISTS_SPEC.md](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md) for detailed architectural constraints.




go test -v ./...