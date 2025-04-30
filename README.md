# ASCON LWC Hash Citadel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) A Python and Django-based web application implementing the ASCON-Hash256 cryptographic hash function. This tool provides a robust and efficient way to generate cryptographic fingerprints for data integrity verification via a user-friendly web interface.

**Note:** This implementation follows the official **NIST SP 800-232 standard for ASCON-Hash256**, utilizing the specified Initialization Vector (IV) and little-endian byte order.

## Overview

This project provides a web interface for generating ASCON-Hash256 (NIST Standard) hashes. ASCON is renowned for its performance in resource-constrained environments (Lightweight Cryptography - LWC), offering strong security guarantees with minimal overhead. While many ASCON implementations exist as libraries or command-line tools, **ASCON LWC Hash Citadel** aims to fill a gap by offering a convenient online platform that supports hashing both direct text input and **file uploads (up to 10MB)**, a feature combination not readily found in other available online ASCON calculators as of late April 2025.

## What is ASCON?

ASCON is a family of lightweight cryptographic algorithms designed for security in environments with limited resources, such as IoT devices, embedded systems, and smart cards. It won the NIST Lightweight Cryptography (LWC) competition and is standardized in **NIST SP 800-232**, highlighting its efficiency and security.

ASCON utilizes a **sponge construction**:
1.  **Absorbing:** The algorithm "soaks up" input data (the message to be hashed) into an internal state (a 320-bit structure).
2.  **Squeezing:** It then "squeezes out" the result – in this case, a fixed-size hash value.

This elegant design allows ASCON to perform various cryptographic tasks using a core permutation function that involves steps like adding constants, non-linear substitutions (S-boxes), and linear diffusion to thoroughly mix the internal state.


**This project (ASCON LWC Hash Citadel) focuses specifically on the ASCON *hashing* function (ASCON-Hash256, NIST Standard) via a web application.**

## How ASCON Hashing Works (ASCON-Hash256 NIST Standard)

ASCON-Hash256 follows the sponge principle according to the NIST standard:

1.  **Initialization:** The internal 320-bit state is initialized with the standard NIST value (`0x00400c0001000100`). The initial permutation (`a`=12 rounds) is applied.
2.  **Absorbing Data:** The input message (from text or file) is padded (append `0x80` and then `0x00` bytes until length is a multiple of the rate). It's processed in blocks (rate = 8 bytes). Each block is XORed into the state (using **little-endian** conversion), followed by applying the ASCON permutation (`b`=12 rounds).
3.  **Squeezing Output:** After absorbing all message blocks (including the final permutation in the absorb phase), the final 256-bit (32-byte) hash value is extracted ("squeezed") from the first four words of the state (using **little-endian** conversion).

## Features

* Implements **ASCON-Hash256 (NIST SP 800-232 standard)**, producing a 32-byte cryptographic hash.
* Uses **little-endian** byte order and the official NIST Initialization Vector.
* Provides a user-friendly **web interface** (built with Django) for generating hashes.
* Accepts both direct **text/string input** and **file uploads**.
* Handles **file sizes up to 10MB** for hashing.

## Implementation Improvements

The core Python hashing utility includes several enhancements focused on code quality, readability, and robustness compared to a basic translation:

* **Centralized Constants:** All core ASCON parameters (IV, Rate, Rounds) and the 64-bit mask are defined centrally for clarity and ease of maintenance.
* **Type Hinting:** Python type hints are used for function signatures and key variables, improving code readability and enabling static analysis checks.
* **Input Validation:** The core hash function includes a runtime check to ensure the input message is of type `bytes`.
* **Precomputed Round Constants:** The ASCON round constants are precomputed, slightly optimizing the permutation loop.
* **Correct 64-bit Handling:** Necessary bitwise masking is consistently applied to handle Python's arbitrary-precision integers correctly.

## Setup and Run Instructions

Follow these steps to get the Django application running locally:

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/dev-loop1/ASCON-LWC-Hash-Citadel.git](https://github.com/dev-loop1/ASCON-LWC-Hash-Citadel.git)
    ```

2.  **Navigate to Project Directory:**
    ```bash
    cd ASCON-LWC-Hash-Citadel
    ```

3.  **Create a Virtual Environment:**
    ```bash
    python -m venv venv
    ```

4.  **Activate the Virtual Environment:**
    * Windows: `venv\Scripts\activate`
    * macOS/Linux: `source venv/bin/activate`

5.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

6.  **Apply Database Migrations:**
    ```bash
    python manage.py migrate
    ```

7.  **Run the Development Server:**
    ```bash
    python manage.py runserver
    ```

8.  **Access the Application:**
    Open your web browser and navigate to `http://127.0.0.1:8000/`.

## References

* **Official ASCON Website & Specification:** [https://ascon.isec.tugraz.at/](https://ascon.isec.tugraz.at/) (Provides general info and links to standard docs)
* **NIST Lightweight Cryptography Project:** [https://csrc.nist.gov/projects/lightweight-cryptography](https://csrc.nist.gov/projects/lightweight-cryptography) (Source for the standard)
* **This Repository:** [https://github.com/dev-loop1/ASCON-LWC-Hash-Citadel](https://github.com/dev-loop1/ASCON-LWC-Hash-Citadel)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.