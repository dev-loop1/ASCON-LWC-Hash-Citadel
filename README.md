# AsconPlayground

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Interactive ASCON Hash Generation, MAC Computation and Forgery Simulation**

AsconPlayground is a Python and Django-based web application designed as an interactive toolkit for utilizing and exploring key functionalities of the ASCON lightweight cryptographic family. It provides tools for ASCON-Hash256, ASCON-MAC, demonstrating MAC-based forgery detection, and visualizing hash output distribution.

**Note on ASCON-Hash256 Implementation:** The ASCON-Hash256 implementation in this project (primarily in `hasher/utils.py`) aims for compliance with ASCON's general principles and uses a parameterized Initialization Vector (IV) construction. This approach is common in some flexible Ascon libraries. For strict comparison with "Ascon-Hash" test vectors from NIST SP 800-232 (which specify a single fixed IV `0x00400c0001000100`), users should be aware of this IV difference. The implementation uses little-endian byte order as specified.

## Overview

AsconPlayground offers a user-friendly web interface for a suite of ASCON-based cryptographic operations. ASCON is renowned for its efficiency in resource-constrained environments (Lightweight Cryptography - LWC) and was selected by NIST for LWC standardization. This toolkit extends beyond simple hashing, providing functionalities for Message Authentication Codes (MACs) for both text and files, an interactive simulation for understanding MAC-based forgery detection, and a tool to visualize the distribution of ASCON-Hash256 outputs. It supports direct text inputs (hex-encoded for hashing keys/tags, UTF-8 for MAC messages) and file uploads (up to 10MB) for most operations.

## What is ASCON?

ASCON is a family of lightweight cryptographic algorithms designed for security in environments with limited resources, such as IoT devices, embedded systems, and smart cards. It won the NIST Lightweight Cryptography (LWC) competition and its hashing and authenticated encryption schemes are included in **NIST SP 800-232**, highlighting its efficiency and security.

ASCON utilizes a **sponge construction**:
1.  **Absorbing:** The algorithm processes input data (the message) by iteratively updating an internal state (a 320-bit structure).
2.  **Squeezing:** It then extracts output (e.g., a hash digest or a MAC tag) from this internal state.

This design uses a core permutation function involving constant additions, non-linear substitutions (S-boxes), and linear diffusion layers to thoroughly mix the internal state, enabling various cryptographic tasks.

**AsconPlayground** provides tools to interact with ASCON-Hash256 and ASCON-MAC.

## How ASCON Cryptographic Functions Work in AsconPlayground

### ASCON-Hash256 (as implemented in `hasher/utils.py`)

The ASCON-Hash256 implementation uses a sponge construction with a 320-bit state and the Ascon permutation.
1.  **Initialization:**
    * The 320-bit state is initialized. The first 8 bytes are set using a parameterized Initialization Vector (IV) constructed from `variant_id=2`, `hash_bitlength=256`, `rate_bytes=8`, and round numbers (`a=12, b=12`), resulting in an IV like `0x0200cc0100080000`. The remaining 32 bytes of the state are zeroed.
    * An initial 12-round Ascon permutation (`P_a`) is applied.
2.  **Absorbing Data:**
    * The input message (from text or file) is padded by appending the byte `0x01` followed by the minimum number of zero bytes to make its length a multiple of the rate (8 bytes).
    * The padded message is processed in 8-byte blocks. Each block is converted from bytes to a 64-bit integer (little-endian) and XORed into the first 64-bit word (`S[0]`) of the state.
    * A 12-round Ascon permutation (`P_b`) is applied after processing each block.
3.  **Squeezing Output:**
    * To produce the 256-bit (32-byte) hash:
        * 8 bytes are extracted from `S[0]` (converted to bytes, little-endian).
        * If more output is needed, the `P_b` permutation is applied.
        * This process (extract 8 bytes from `S[0]`, permute if needed) is repeated until all 32 bytes of the hash are generated.

### ASCON-MAC (Message Authentication Code - using `hasher/ascon.py`)

ASCON-MAC is used to ensure both data integrity and authenticity using a secret key.
1.  **Initialization:** The 320-bit state is initialized using the 16-byte secret key and MAC-specific domain separation parameters (derived from key length, rate, rounds, etc., as per Ascon specifications). An initial `a`-round Ascon permutation is applied.
2.  **Absorbing Message:** The input message (text or file content) is padded (typically `0x01` followed by zeros) to be a multiple of the MAC's input rate (32 bytes for the "Ascon-Mac" variant). Each block is XORed into the rate portion of the state. A `b`-round Ascon permutation is applied after each block.
3.  **Finalization & Squeezing Tag:** A final `a`-round permutation is applied. The 16-byte (128-bit) MAC tag is then extracted (squeezed) from the state.

## Features

* **ASCON-Hash256 Generation:**
    * Computes 256-bit (32-byte) digests for text inputs (interpreted as hexadecimal strings).
    * Computes digests for uploaded file contents.
    * Uses little-endian byte order and a parameterized IV construction for hashing.
* **ASCON-MAC Operations:**
    * Generates 128-bit (16-byte) MAC tags for text messages (UTF-8 encoded) or file contents using a 128-bit (16-byte) secret key.
    * Verifies provided MAC tags against a message/file and key.
* **Digital Signature Forgery Simulation (Text MAC):**
    * Interactively demonstrates how MACs detect tampering in text messages.
    * Preserves whitespace changes (`strip=False`) for accurate simulation.
    * Uses Django sessions to carry data from MAC generation to the simulation.
* **Hash Distribution Visualization:**
    * Generates a 2D scatter plot (using Chart.js) from the first 4 bytes of multiple ASCON-Hash256 outputs derived from slight variations of a base string.
    * Provides a simplified visual insight into the hash function's pseudo-random output distribution and avalanche effect.
* **User-Friendly Web Interface:**
    * Built with Django, featuring a tabbed interface for easy navigation between tools.
    * Supports file uploads up to 10MB.
    * Provides clear feedback and results.

## Implementation Improvements in Hashing (`hasher/utils.py`)

The core Python ASCON-Hash256 implementation (`hasher/utils.py`) includes several performance and memory efficiency enhancements, ensuring consistency with the reference "Ascon-Hash256" variant it's based on (while noting the IV difference from the NIST standard fixed IV):

1.  **Streaming Message Absorption:**
    * **Improvement:** Processes input messages in 8-byte chunks directly using slicing, rather than concatenating the entire message with padding upfront. The final padded block is handled separately.
    * **Benefit:** Reduces peak memory usage significantly for large inputs (from O(MessageLength) to O(BlockSize)), improving responsiveness.

2.  **Built-in Byte/Integer Conversions:**
    * **Improvement:** Uses Python's optimized built-in methods `int.from_bytes(data, 'little')` and `integer.to_bytes(len, 'little')` instead of potentially slower pure Python loop-based conversions.
    * **Benefit:** Faster data type conversions.

3.  **Pre-computed Round Constants:**
    * **Improvement:** The twelve 64-bit Ascon round constants are pre-calculated and stored globally.
    * **Benefit:** Avoids repeated arithmetic for these constants in every round of every permutation.

4.  **Localized Round Constant Access in Permutation:**
    * **Improvement:** The global `ROUND_CONSTANTS` list is assigned to a local variable within `ascon_permutation` for lookups.
    * **Benefit:** Minor speed-up due to faster local variable access in Python loops.

5.  **Unrolled S-box Layer:**
    * **Improvement:** Operations for the 5 state words in the S-box layer are written out explicitly, avoiding Python loop overhead.
    * **Benefit:** Potential speed gain by reducing loop setup/iteration costs for small, fixed iterations.

6.  **Efficient Hash Accumulation:**
    * **Improvement:** A mutable `bytearray` with `extend()` is used to build the hash output incrementally during squeezing, converted to `bytes` once at the end.
    * **Benefit:** Faster and more memory-efficient than repeated concatenation of immutable `bytes` objects.

7.  **Direct Byte Literals & Simplified Padding Logic:**
    * **Improvement:** Uses direct byte literals (e.g., `b'\x01'`). Padding calculation logic was streamlined.
    * **Benefit:** Slightly cleaner code and potential micro-optimizations.

8.  **Careful 64-bit Unsigned Arithmetic:**
    * **Improvement:** Explicit masking (`& 0xFFFFFFFFFFFFFFFF`) ensures Python's arbitrary-precision integers conform to Ascon's 64-bit word operations, especially for bitwise NOT (`val ^ MASK_64`).
    * **Benefit:** Ensures cryptographic correctness and consistency with fixed-size register behavior.

## Setup and Run Instructions

Follow these steps to get the Django application running locally:

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/dev-loop1/AsconPlayground.git](https://github.com/dev-loop1/AsconPlayground.git)
    cd AsconPlayground 
    ```

2.  **Create & Activate Virtual Environment:**
    ```bash
    python -m venv venv
    # Windows:
    # venv\Scripts\activate
    # macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Apply Database Migrations (for session table, etc.):**
    ```bash
    python manage.py migrate
    ```

5.  **Run the Development Server:**
    ```bash
    python manage.py runserver
    ```

6.  **Access the Application:**
    Open your web browser and navigate to `http://127.0.0.1:8000/`.

## References

* **Official ASCON Website & Specification:** [https://ascon.isec.tugraz.at/](https://ascon.isec.tugraz.at/)
* **NIST Lightweight Cryptography Project (NIST SP 800-232):** [https://csrc.nist.gov/projects/lightweight-cryptography](https://csrc.nist.gov/projects/lightweight-cryptography)
* **pyascon Library (source of `hasher/ascon.py`):** [https://github.com/meichlseder/pyascon](https://github.com/meichlseder/pyascon)
* **This Repository:** [https://github.com/dev-loop1/AsconPlayground](https://github.com/dev-loop1/AsconPlayground)

## Contributors
| Name             | Enrollment No. |
| -------------------- | -------------------- |
| Vikas Kumar          | 22114106             |
| Adarsh Dehariya      | 22114002             |

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
