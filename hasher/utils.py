# -*- coding: utf-8 -*-
"""
ASCON-Hash256 Implementation (NIST SP 800-232 Standard).

This module provides a Python implementation of the ASCON-Hash256 cryptographic
hash function as specified in the NIST SP 800-232 standard.
It produces a 256-bit digest and uses little-endian byte order internally.

This module is intended for use as a utility function, for example, within
a Django application's utils.py.
"""

from typing import List, Tuple, Union

# --- Constants (NIST SP 800-232 Standard) ---

ASCON_HASH256_IV: int = 0x00400c0001000100
"""Initialization Vector for ASCON-Hash256 (NIST SP 800-232)."""

ASCON_HASH_RATE: int = 8
"""Rate in bytes (64 bits) for ASCON-Hash."""

ASCON_HASH_PA_ROUNDS: int = 12
"""Number of permutation rounds for initialization and finalization (a-rounds)."""

ASCON_HASH_PB_ROUNDS: int = 12
"""Number of permutation rounds for absorbing data blocks (b-rounds)."""

MASK_64: int = 0xFFFFFFFFFFFFFFFF
"""Mask to ensure 64-bit unsigned integer representation in Python."""

# Precomputed round constants for the ASCON permutation (12 rounds).
# These constants remain the same for the NIST standard permutation.
# Derived from the formula: (0xf0 - r*0x10 + r*0x1) for r in 0..11
ASCON_ROUND_CONSTANTS: Tuple[int, ...] = (
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
)

# Type alias for the internal state (list of 5 64-bit integers).
StateType = List[int]


# --- Helper Functions (Unaffected by IV/Endianness Change) ---

def right_rot(x: int, n: int) -> int:
    """
    Perform a right rotation on a 64-bit integer.

    Args:
        x: The 64-bit integer value (Python int).
        n: The number of bits to rotate right.

    Returns:
        The result of the right rotation, masked to 64 bits.
    """
    x &= MASK_64  # Ensure input is treated as 64-bit
    return ((x >> n) | (x << (64 - n))) & MASK_64


def sbox(state: StateType) -> StateType:
    """
    Apply the ASCON substitution layer (S-box) to the state in-place.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.

    Returns:
        The modified cipher state.
    """
    x0, x1, x2, x3, x4 = state

    x0 ^= x4
    x4 ^= x3
    x2 ^= x1
    t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4 # Intermediate state

    t0 = (~t0) & t1
    t1 = (~t1) & t2
    t2 = (~t2) & t3
    t3 = (~t3) & t4
    t4 = (~t4) & x0

    x0 ^= t1
    x1 ^= t2
    x2 ^= t3
    x3 ^= t4
    x4 ^= t0

    x1 ^= x0
    x0 ^= x4
    x3 ^= x2
    x2 = ~x2

    # Ensure 64-bit bounds using mask
    state[0] = x0 & MASK_64
    state[1] = x1 & MASK_64
    state[2] = x2 & MASK_64
    state[3] = x3 & MASK_64
    state[4] = x4 & MASK_64
    return state


def linear_layer(state: StateType) -> StateType:
    """
    Apply the ASCON linear diffusion layer to the state in-place.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.

    Returns:
        The modified cipher state.
    """
    x0, x1, x2, x3, x4 = state

    x0 ^= right_rot(x0, 19) ^ right_rot(x0, 28)
    x1 ^= right_rot(x1, 61) ^ right_rot(x1, 39)
    x2 ^= right_rot(x2, 1)  ^ right_rot(x2, 6)
    x3 ^= right_rot(x3, 10) ^ right_rot(x3, 17)
    x4 ^= right_rot(x4, 7)  ^ right_rot(x4, 41)

    # Ensure 64-bit bounds using mask
    state[0] = x0 & MASK_64
    state[1] = x1 & MASK_64
    state[2] = x2 & MASK_64
    state[3] = x3 & MASK_64
    state[4] = x4 & MASK_64
    return state


def ascon_permutation(state: StateType, rounds: int) -> StateType:
    """
    Apply the ASCON permutation (p) to the state for a specified number of rounds.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.
        rounds: The number of rounds of the permutation to apply.

    Returns:
        The modified cipher state after applying the permutation rounds.
    """
    start_round = 12 - rounds
    for r in range(start_round, 12):
        # 1. Add round constant (XOR into state[2])
        state[2] ^= ASCON_ROUND_CONSTANTS[r]

        # 2. Substitution layer (S-box)
        state = sbox(state) # Modifies state in-place

        # 3. Linear diffusion layer
        state = linear_layer(state) # Modifies state in-place

    return state


# --- Core Hashing Functions (NIST Standard Version) ---

def initialize_hash() -> StateType:
    """
    Initialize the ASCON-Hash state according to NIST SP 800-232.

    Sets up the initial 320-bit state using the official NIST ASCON-Hash256 IV
    and applies the initial 'a' rounds (12) of the permutation.

    Returns:
        The initialized cipher state (list of 5 ints).
    """
    # Initialize state using the NIST standard IV for ASCON-Hash256
    initial_state: StateType = [ASCON_HASH256_IV, 0, 0, 0, 0]

    # Apply the 'a' rounds of permutation for initialization.
    return ascon_permutation(initial_state, ASCON_HASH_PA_ROUNDS)


def absorb(state: StateType, message: bytes) -> StateType:
    """
    Absorb the input message into the ASCON state (NIST standard).

    Pads the message, processes it in blocks, and applies the permutation
    after each block using little-endian byte order. Modifies the state in-place.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.
        message: The message data (bytes) to absorb.

    Returns:
        The modified cipher state after absorbing the entire message.
    """
    padded_message = bytearray(message)

    # Standard padding: Append 0x80 then zeros until length is multiple of RATE.
    msg_len = len(message)
    # Calculate number of padding zero bytes needed (excluding the 0x80)
    padding_zero_bytes = (ASCON_HASH_RATE - 1 - (msg_len % ASCON_HASH_RATE)) % ASCON_HASH_RATE
    padded_message.append(0x80)  # Append the single '1' bit padding marker.
    padded_message.extend(bytes(padding_zero_bytes)) # Append '0' bit padding bytes.

    # Process the padded message in blocks.
    for i in range(0, len(padded_message), ASCON_HASH_RATE):
        block = padded_message[i : i + ASCON_HASH_RATE]

        # XOR the message block into the first 'rate' part of the state.
        # NIST standard uses LITTLE-ENDIAN byte order.
        block_int = int.from_bytes(block, byteorder='little')
        state[0] ^= block_int

        # Apply the 'b' rounds of permutation after processing each block.
        state = ascon_permutation(state, ASCON_HASH_PB_ROUNDS)

    return state


def squeeze(state: StateType) -> bytes:
    """
    Squeeze the 256-bit (32-byte) hash digest from the final state (NIST standard).

    Extracts the required number of bytes using little-endian byte order.

    Args:
        state: The final cipher state after absorbing all data.

    Returns:
        The 32-byte hash digest.
    """
    digest_len_bytes = 32
    digest = bytearray()

    # The final permutation was applied in the absorb phase.
    # Extract the first 256 bits (32 bytes) from the state.
    idx = 0
    while len(digest) < digest_len_bytes:
        bytes_to_take = min(ASCON_HASH_RATE, digest_len_bytes - len(digest))
        if bytes_to_take <= 0:
            break

        word_value = state[idx] & MASK_64
        # Convert the state word to bytes using LITTLE-ENDIAN (NIST standard).
        word_bytes = word_value.to_bytes(8, byteorder='little')
        # Append the required number of bytes from the current word.
        digest.extend(word_bytes[:bytes_to_take])

        idx += 1 # Move to the next state word for extraction.

    return bytes(digest) # Return immutable bytes object.


# --- Main Public Function (NIST Standard Version) ---

def ascon_hash256(message: bytes) -> bytes:
    """
    Compute the ASCON-Hash256 digest according to NIST SP 800-232 standard.

    This function implements the official NIST standard using little-endian
    byte order and the specified Initialization Vector.

    Args:
        message: The message data (bytes) to hash.

    Returns:
        The 32-byte (256-bit) hash digest as a bytes object.

    Raises:
        TypeError: If the input message is not of type bytes.
    """
    # 1. Validate Input Type
    if not isinstance(message, bytes):
        raise TypeError("Input message must be bytes.")

    # 2. Initialize state (using NIST IV)
    state: StateType = initialize_hash()

    # 3. Absorb message into state (using little-endian)
    state = absorb(state, message)

    # 4. Squeeze the final hash digest from the state (using little-endian)
    return squeeze(state)