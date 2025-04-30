"""
ASCON-Hash v1.2 Implementation (Big-Endian).

This module provides a Python implementation of the ASCON-Hash cryptographic
hash function as specified in the original Ascon v1.2 submission.
It produces a 256-bit digest and uses big-endian byte order internally.

This module is intended for use as a utility function, for example, within
a Django application's utils.py.

Note: This implementation differs from the final NIST SP 800-232 standard
which specifies little-endian byte order and uses different Initialization Vectors.
"""

from typing import List, Tuple, Union

# --- Constants ---

ASCON_HASH_IV: int = 0x00400c0000000100
"""Initialization Vector for ASCON-Hash v1.2."""

ASCON_HASH_RATE: int = 8
"""Rate in bytes (64 bits) for ASCON-Hash."""

ASCON_HASH_PA_ROUNDS: int = 12
"""Number of permutation rounds for initialization and finalization (a-rounds)."""

ASCON_HASH_PB_ROUNDS: int = 12
"""Number of permutation rounds for absorbing data blocks (b-rounds)."""

MASK_64: int = 0xFFFFFFFFFFFFFFFF
"""Mask to ensure 64-bit unsigned integer representation in Python."""

# Precomputed round constants for the ASCON permutation (12 rounds).
# Derived from the formula: (0xf0 - r*0x10 + r*0x1) for r in 0..11
ASCON_ROUND_CONSTANTS: Tuple[int, ...] = (
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
)

# Type alias for the internal state (list of 5 64-bit integers).
StateType = List[int]


# --- Helper Functions ---

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

    This function implements the 5-bit S-box applied bitwise across the
    64-bit words of the state.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.

    Returns:
        The modified cipher state.
    """
    x0, x1, x2, x3, x4 = state

    # S-box layer computation using bitwise operations.
    x0 ^= x4
    x4 ^= x3
    x2 ^= x1
    # Intermediate variables (t) can aid readability of the S-box logic.
    t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4

    t0 = (~t0) & t1
    t1 = (~t1) & t2
    t2 = (~t2) & t3
    t3 = (~t3) & t4
    t4 = (~t4) & x0  # Use original x0 for this step

    x0 ^= t1
    x1 ^= t2
    x2 ^= t3
    x3 ^= t4
    x4 ^= t0

    x1 ^= x0
    x0 ^= x4
    x3 ^= x2
    x2 = ~x2 # Bitwise NOT operation

    # Ensure all state words remain within 64-bit bounds after S-box.
    state[0] = x0 & MASK_64
    state[1] = x1 & MASK_64
    state[2] = x2 & MASK_64
    state[3] = x3 & MASK_64
    state[4] = x4 & MASK_64
    return state


def linear_layer(state: StateType) -> StateType:
    """
    Apply the ASCON linear diffusion layer to the state in-place.

    This layer provides diffusion by rotating and XORing each state word.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.

    Returns:
        The modified cipher state.
    """
    x0, x1, x2, x3, x4 = state

    # Apply linear diffusion sigma functions based on the specification.
    # Sigma_0: rotations 19, 28
    x0 ^= right_rot(x0, 19) ^ right_rot(x0, 28)
    # Sigma_1: rotations 61, 39
    x1 ^= right_rot(x1, 61) ^ right_rot(x1, 39)
    # Sigma_2: rotations 1, 6
    x2 ^= right_rot(x2, 1)  ^ right_rot(x2, 6)
    # Sigma_3: rotations 10, 17
    x3 ^= right_rot(x3, 10) ^ right_rot(x3, 17)
    # Sigma_4: rotations 7, 41
    x4 ^= right_rot(x4, 7)  ^ right_rot(x4, 41)

    # Ensure all state words remain within 64-bit bounds after diffusion.
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
        rounds: The number of rounds of the permutation to apply (e.g., 12, 8, 6).

    Returns:
        The modified cipher state after applying the permutation rounds.
    """
    # The rounds are indexed from 12-rounds to 11 for constants lookup.
    start_round = 12 - rounds
    for r in range(start_round, 12):
        # 1. Add round constant (XOR into state[2])
        state[2] ^= ASCON_ROUND_CONSTANTS[r]

        # 2. Substitution layer (S-box)
        state = sbox(state) # Modifies state in-place

        # 3. Linear diffusion layer
        state = linear_layer(state) # Modifies state in-place

    return state


# --- Core Hashing Functions ---

def initialize_hash() -> StateType:
    """
    Initialize the ASCON-Hash state.

    Sets up the initial 320-bit state using the ASCON-Hash v1.2 IV and applies
    the initial 'a' rounds of the permutation.

    Returns:
        The initialized cipher state (list of 5 ints).
    """
    # State is represented as 5 64-bit integers.
    initial_state: StateType = [ASCON_HASH_IV, 0, 0, 0, 0]

    # Apply the 'a' rounds of permutation for initialization.
    return ascon_permutation(initial_state, ASCON_HASH_PA_ROUNDS)


def absorb(state: StateType, message: bytes) -> StateType:
    """
    Absorb the input message into the ASCON state using the sponge construction.

    Pads the message, processes it in blocks, and applies the permutation
    after each block. Modifies the state in-place.

    Args:
        state: The current cipher state (list of 5 ints). Modified in-place.
        message: The message data (bytes) to absorb.

    Returns:
        The modified cipher state after absorbing the entire message.
    """
    # Ensure message data is mutable for padding.
    padded_message = bytearray(message)

    # Calculate padding length: Append 0x80 then zeros until multiple of RATE.
    msg_len = len(message)
    padding_len = ASCON_HASH_RATE - (msg_len % ASCON_HASH_RATE)
    padded_message.append(0x80)  # Append the single '1' bit padding marker.
    padded_message.extend(bytes(padding_len - 1)) # Append '0' bit padding bytes.

    # Process the padded message in blocks.
    for i in range(0, len(padded_message), ASCON_HASH_RATE):
        block = padded_message[i : i + ASCON_HASH_RATE]

        # XOR the message block into the first 'rate' part of the state.
        # This implementation uses BIG-ENDIAN byte order (Ascon v1.2).
        block_int = int.from_bytes(block, byteorder='big')
        state[0] ^= block_int

        # Apply the 'b' rounds of permutation after processing each block.
        state = ascon_permutation(state, ASCON_HASH_PB_ROUNDS)

    return state


def squeeze(state: StateType) -> bytes:
    """
    Squeeze the 256-bit (32-byte) hash digest from the final state.

    Args:
        state: The final cipher state after absorbing all data.

    Returns:
        The 32-byte hash digest.
    """
    digest_len_bytes = 32
    # Use bytearray for efficient concatenation during extraction.
    digest = bytearray()

    # Ascon-Hash256 requires 32 bytes. The rate is 8 bytes.
    # Extract 8 bytes from state[0], state[1], state[2], state[3].
    # The final permutation was already applied in the absorb phase.
    idx = 0
    while len(digest) < digest_len_bytes:
        # Calculate how many bytes to take in this iteration (max is RATE).
        bytes_to_take = min(ASCON_HASH_RATE, digest_len_bytes - len(digest))
        if bytes_to_take <= 0:
            # This condition prevents infinite loops if logic were different.
            break

        word_value = state[idx] & MASK_64
        # Convert the state word to bytes using BIG-ENDIAN (Ascon v1.2).
        word_bytes = word_value.to_bytes(8, byteorder='big')
        # Append the required number of bytes from the current word.
        digest.extend(word_bytes[:bytes_to_take])

        idx += 1 # Move to the next state word for extraction.

    return bytes(digest) # Return immutable bytes object.


# --- Main Public Function ---

def ascon_hash256(message: bytes) -> bytes:
    """
    Compute the ASCON-Hash (256-bit digest) of the input message.

    This function implements the Ascon v1.2 specification using big-endian
    byte order and the corresponding Initialization Vector. It is the primary
    interface intended for use by other modules.

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

    # 2. Initialize state
    state: StateType = initialize_hash()

    # 3. Absorb message into state
    state = absorb(state, message)

    # 4. Squeeze the final hash digest from the state
    return squeeze(state)