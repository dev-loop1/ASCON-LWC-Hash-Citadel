
""" ASCON-Hash256 Implementation """

from typing import List

# Global debug flags
debug = False
debugpermutation = False

# Type alias for the internal state (list of 5 64-bit integers)
StateType = List[int]

# Pre-computed Ascon Round Constants for 12 rounds
# Optimization: Constants are defined once
ROUND_CONSTANTS = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
]

# === HELPER FUNCTIONS ===

def zero_bytes(n: int) -> bytes:
    """Returns n zero bytes."""
    return n * b"\x00"

def to_bytes(data) -> bytes:
    """Converts input (list, bytearray, or bytes) to a bytes object."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    return bytes(bytearray(data)) # Assumes data is a list of int byte values

def bytes_to_int(byte_sequence: bytes) -> int:
    """Converts little-endian bytes to int."""
    # Optimization: Uses fast built-in method
    return int.from_bytes(byte_sequence, 'little')

def bytes_to_state(byte_sequence: bytes) -> StateType:
    """Converts 40-byte sequence to 5-word Ascon state."""
    # Each word is 8 bytes (64 bits)
    return [bytes_to_int(byte_sequence[8 * w : 8 * (w + 1)]) for w in range(5)]

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    """Converts int to nbytes little-endian bytes."""
    if integer < 0:
        # Safeguard; should not be reached with correct 64-bit unsigned handling
        raise ValueError("Cannot convert negative integer to unsigned bytes directly.")
    # Optimization: Uses fast built-in method
    return integer.to_bytes(nbytes, 'little')

def rotr(val: int, r: int) -> int:
    """Performs a 64-bit right rotation."""
    val_64 = val & 0xFFFFFFFFFFFFFFFF # Ensure 64-bit unsigned
    r %= 64 # Rotation within 0-63 bits
    # Optimization: Careful 64-bit unsigned arithmetic
    return ((val_64 >> r) | (val_64 << (64 - r))) & 0xFFFFFFFFFFFFFFFF

# --- Debug Printing Functions ---

def printstate(S: StateType, description: str = ""):
    """Prints the full Ascon state (hex)."""
    if debug:
        print(f" {description}")
        print(" ".join([f"{s:016x}" for s in S]))

def printwords(S: StateType, description: str = ""):
    """Prints Ascon state words individually (hex)."""
    if debugpermutation:
        print(f" {description}")
        print("\n".join([f"  x{i}={s_val:016x}" for i, s_val in enumerate(S)]))

# === ASCON PERMUTATION (p) ===

def ascon_permutation(S: StateType, rounds: int = 12):
    """Applies the Ascon permutation to state S (modified in-place)."""
    assert 1 <= rounds <= 12
    if debugpermutation: printwords(S, "permutation input:")

    mask64 = 0xFFFFFFFFFFFFFFFF # For 64-bit unsigned NOT operation
    # Optimization: Local access to round constants
    local_round_constants = ROUND_CONSTANTS

    # --- Permutation Rounds ---
    for r_loop_idx in range(12 - rounds, 12): # Effective round index 0..11
        # --- Stage 1: Add Round Constant (p_C) ---
        S[2] ^= local_round_constants[r_loop_idx]
        if debugpermutation: printwords(S, f"after round constant (r_idx={r_loop_idx}):")

        # --- Stage 2: Substitution Layer (p_S) ---
        # Optimization: S-box layer is unrolled
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]

        # T_i = ~S_i & S_{(i+1)%5} (64-bit unsigned NOT is S_i ^ mask64)
        t0 = (S[0] ^ mask64) & S[1]
        t1 = (S[1] ^ mask64) & S[2]
        t2 = (S[2] ^ mask64) & S[3]
        t3 = (S[3] ^ mask64) & S[4]
        t4 = (S[4] ^ mask64) & S[0]

        # S_i ^= T_{(i+1)%5}
        S[0] ^= t1
        S[1] ^= t2
        S[2] ^= t3
        S[3] ^= t4
        S[4] ^= t0
        
        # Final S-box XORs
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= mask64 # S_2 = ~S_2 (64-bit unsigned inversion)
        if debugpermutation: printwords(S, "after substitution layer:")

        # --- Stage 3: Linear Diffusion Layer (p_L) ---
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)
        if debugpermutation: printwords(S, "after linear diffusion layer:")

# === CORE ASCON-HASH256 LOGIC ===

def _core_reference_ascon_hash256(message: bytes) -> bytes:
    """Implements Ascon-Hash256 logic (meichlseder/pyascon variant)."""
    # Parameters for "Ascon-Hash256"
    variant_id_for_iv = 2
    a_rounds = 12           # Initial permutation rounds
    b_rounds = 12           # Intermediate/squeezing rounds
    rate_bytes = 8          # Hashing rate in bytes
    hash_len_bytes = 32     # Output hash length
    iv_taglen_bits = 256    # IV parameter

    # --- Stage 1: Initialization ---
    iv_construction_part1 = to_bytes([variant_id_for_iv, 0, (b_rounds << 4) + a_rounds])
    iv_construction_part2 = int_to_bytes(iv_taglen_bits, 2) 
    iv_construction_part3 = to_bytes([rate_bytes, 0, 0])
    iv = iv_construction_part1 + iv_construction_part2 + iv_construction_part3
    
    S: StateType = bytes_to_state(iv + zero_bytes(32)) # Initial state
    if debug: printstate(S, "Initial state (reference IV):")

    ascon_permutation(S, a_rounds) # Apply P_a
    if debug: printstate(S, "State after initialization permutation:")

    # --- Stage 2: Message Processing (Absorbing) ---
    # Optimization: Streaming message absorption for memory efficiency
    num_full_blocks = len(message) // rate_bytes
    for i in range(num_full_blocks):
        block_data = message[i * rate_bytes : (i + 1) * rate_bytes]
        S[0] ^= bytes_to_int(block_data) # XOR message block into S[0]
        ascon_permutation(S, b_rounds)   # Apply P_b

    # Construct and absorb the final padded block
    last_partial_message_block = message[num_full_blocks * rate_bytes:]
    
    len_mod_rate_orig_msg = len(message) % rate_bytes
    # Optimization: Simplified padding calculation
    num_padding_zeros = (rate_bytes - 1 - len_mod_rate_orig_msg) % rate_bytes
    # Optimization: Direct byte literal for 0x01
    padding_bytes = b'\x01' + zero_bytes(num_padding_zeros) 
    
    final_block_to_absorb = last_partial_message_block + padding_bytes
    assert len(final_block_to_absorb) == rate_bytes, \
        f"Internal error: Final block length mismatch: {len(final_block_to_absorb)} vs {rate_bytes}"

    S[0] ^= bytes_to_int(final_block_to_absorb) # XOR final block
    ascon_permutation(S, b_rounds)              # Apply P_b
    if debug: printstate(S, "State after message absorption (final block):")

    # --- Stage 3: Finalization (Squeezing) ---
    # Optimization: Use bytearray for efficient hash accumulation
    H_byte_array = bytearray()
    while len(H_byte_array) < hash_len_bytes:
        H_byte_array.extend(int_to_bytes(S[0], rate_bytes)) # Extract rate_bytes from S[0]
        if len(H_byte_array) < hash_len_bytes:         # If more output is needed
            ascon_permutation(S, b_rounds)             # Permute the state (P_b)
    if debug: printstate(S, "State after squeezing completion:")

    return bytes(H_byte_array[:hash_len_bytes]) # Return requested hash length

# === API ===

def ascon_hash256(message: bytes) -> bytes:
    """
    Computes an Ascon-based 256-bit hash of a message.
    
    Args:
        message: The message data (bytes) to hash.

    Returns:
        The 32-byte (256-bit) hash digest as a bytes object.
    """
    if not isinstance(message, bytes):
        raise TypeError("Input message must be bytes.")
    return _core_reference_ascon_hash256(message)
