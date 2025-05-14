
""" ASCON-Hash256 Implementation. """

from typing import List 

# Global debug flags
debug = False
debugpermutation = False

# Type alias for the internal state
StateType = List[int] 

# === HELPER FUNCTIONS ===

def zero_bytes(n: int) -> bytes:
    """Returns n zero bytes."""
    return n * b"\x00"

def to_bytes(data) -> bytes:
    """Converts input (list of ints, bytearray, or bytes) to a bytes object."""
    if isinstance(data, bytes): return data
    if isinstance(data, bytearray): return bytes(data)
    return bytes(bytearray(data)) 

def bytes_to_int(byte_sequence: bytes) -> int:
    """Converts a little-endian byte sequence to an integer."""
    val = 0
    # to_bytes ensures byte_sequence is iterable bytes if it was originally a list
    processed_bytes = to_bytes(byte_sequence) 
    for i, b_val in enumerate(processed_bytes):
        val |= b_val << (i * 8)
    return val

def bytes_to_state(byte_sequence: bytes) -> StateType:
    """Converts a 40-byte sequence into a 5-word (64-bit each) Ascon state."""
    return [bytes_to_int(byte_sequence[8*w : 8*(w+1)]) for w in range(5)]

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    """Converts an integer to a little-endian byte sequence of nbytes."""
    return to_bytes([(integer >> (i * 8)) & 0xFF for i in range(nbytes)])

def rotr(val: int, r: int) -> int:
    """Performs a 64-bit right rotation on val by r bits."""
    val_64 = val & 0xFFFFFFFFFFFFFFFF # Ensure val is treated as a 64-bit value
    r %= 64 # Ensure r is within the 0-63 range
    return ((val_64 >> r) | (val_64 << (64 - r))) & 0xFFFFFFFFFFFFFFFF

# --- Debug Printing Functions (active if debug flags are True) ---

def printstate(S: StateType, description: str = ""):
    """Prints the full Ascon state."""
    if debug:
        print(f" {description}")
        print(" ".join([f"{s:016x}" for s in S]))

def printwords(S: StateType, description: str = ""):
    """Prints Ascon state words individually."""
    if debugpermutation:
        print(f" {description}")
        print("\n".join([f"  x{i}={s:016x}" for i, s in enumerate(S)]))

# === ASCON PERMUTATION (p) ===

def ascon_permutation(S: StateType, rounds: int = 12):
    """
    Applies the Ascon permutation to the state S.
    S is modified in-place.
    """
    assert 1 <= rounds <= 12
    if debugpermutation: printwords(S, "permutation input:")

    for r_idx in range(12 - rounds, 12): # r_idx is the effective round index 0..11
        # Add Round Constant (p_C)
        S[2] ^= (0xf0 - r_idx*0x10 + r_idx*0x1)
        if debugpermutation: printwords(S, f"after round constant (r={r_idx}):")
        
        # Substitution Layer (p_S)
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)] # T_i = ~S_i & S_{i+1}
        for i in range(5):
            S[i] ^= T[(i+1)%5] # S_i ^= T_{i+1}
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0xFFFFFFFFFFFFFFFF # S_2 = ~S_2
        if debugpermutation: printwords(S, "after substitution layer:")
        
        # Linear Diffusion Layer (p_L)
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)
        if debugpermutation: printwords(S, "after linear diffusion layer:")

# === CORE ASCON-HASH256 LOGIC ===

def _core_reference_ascon_hash256(message: bytes) -> bytes:

    # Parameters for "Ascon-Hash256" 
    variant_id_for_iv = 2
    a_rounds = 12           # Number of initial permutation rounds
    b_rounds = 12           # Number of intermediate/squeezing permutation rounds
    rate_bytes = 8          # Rate in bytes for hashing
    hash_len_bytes = 32     # Fixed output length for Ascon-Hash256
    iv_taglen_bits = 256    # Output length in bits for IV construction 

    # 1. Initialization Phase
    # IV construction
    iv = to_bytes([variant_id_for_iv, 0, (b_rounds<<4) + a_rounds]) + \
         int_to_bytes(iv_taglen_bits, 2) + \
         to_bytes([rate_bytes, 0, 0])
    
    S: StateType = bytes_to_state(iv + zero_bytes(32)) # Initial state
    if debug: printstate(S, "Initial state (reference IV):")

    ascon_permutation(S, a_rounds) # Apply P_a
    if debug: printstate(S, "State after initialization permutation:")

    # 2. Message Processing Phase (Absorbing)
    # If len(message) is a multiple of rate_bytes, a full new block of padding is added.
    if len(message) % rate_bytes == 0:
        m_padded = message + (to_bytes([0x01]) + zero_bytes(rate_bytes - 1))
    else:
        # Fill the current block with 0x01 followed by zeros
        padding_suffix = to_bytes([0x01]) + \
                         zero_bytes(rate_bytes - (len(message) % rate_bytes) - 1)
        m_padded = message + padding_suffix
    
    # Absorb padded message blocks
    for block_offset in range(0, len(m_padded), rate_bytes):
        block_data = m_padded[block_offset : block_offset + rate_bytes]
        S[0] ^= bytes_to_int(block_data) # XOR message block into S[0]
        ascon_permutation(S, b_rounds)   # Apply P_b
    if debug: printstate(S, "State after message absorption:")

    # 3. Finalization Phase (Squeezing)
    
    H = b""
    while len(H) < hash_len_bytes:
        H += int_to_bytes(S[0], rate_bytes) 
        if len(H) < hash_len_bytes:         
            ascon_permutation(S, b_rounds)  
    if debug: printstate(S, "State after squeezing completion:")

    return H[:hash_len_bytes]

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