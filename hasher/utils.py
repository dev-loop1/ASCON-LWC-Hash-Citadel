def ascon_hash256(message):
    """
    Compute the ASCON-Hash (256 bits) of the input message.
    
    Args:
        message (bytes): The message to hash
        
    Returns:
        bytes: The 32-byte (256-bit) hash digest
    """
    # Initialize the state
    state = initialize_hash()
    
    # Absorb the message
    state = absorb(state, message)
    
    # Squeeze the output
    return squeeze(state)

def initialize_hash():
    """Initialize the ASCON-Hash state with the IV and zeros."""
    # Constants for ASCON
    ASCON_HASH_IV = 0x00400c0000000100  # Initialization vector for ASCON-Hash
    ASCON_HASH_PA_ROUNDS = 12  # Number of rounds for initialization

    # State is represented as 5 64-bit integers
    state = [ASCON_HASH_IV, 0, 0, 0, 0]
    
    # Apply the permutation with a rounds
    state = ascon_permutation(state, ASCON_HASH_PA_ROUNDS)
    
    return state

def absorb(state, message):
    """Absorb the message into the state."""
    # Constants
    ASCON_HASH_RATE = 8  # Rate (number of bytes absorbed per permutation)
    ASCON_HASH_PB_ROUNDS = 12  # Number of rounds for processing data
    
    # Pad the message to a multiple of the rate
    padded_message = bytes(message)  # Create a copy to ensure we don't modify the input
    
    # Add padding byte 0x80 followed by zeros
    if len(message) % ASCON_HASH_RATE == 0 and len(message) > 0:
        padded_message = padded_message + b'\x80' + bytes(ASCON_HASH_RATE - 1)
    else:
        padded_message = padded_message + b'\x80' + bytes(ASCON_HASH_RATE - (len(message) % ASCON_HASH_RATE) - 1)
    
    # Process the message in blocks of size RATE
    for i in range(0, len(padded_message), ASCON_HASH_RATE):
        block = padded_message[i:i+ASCON_HASH_RATE]
        
        # XOR the block into the state (only into the first RATE bytes)
        block_int = int.from_bytes(block, byteorder='big')
        state[0] ^= block_int
        
        # Apply permutation except for the last block
        if i + ASCON_HASH_RATE < len(padded_message):
            state = ascon_permutation(state, ASCON_HASH_PB_ROUNDS)
    
    return state

def squeeze(state):
    """Squeeze the hash digest from the state."""
    # Constants
    ASCON_HASH_PA_ROUNDS = 12  # Number of rounds for finalization
    
    # Apply the permutation with a rounds for finalization
    state = ascon_permutation(state, ASCON_HASH_PA_ROUNDS)
    
    # Extract the hash value (256 bits = 32 bytes) from the state
    digest = b''
    
    # We need to extract 32 bytes from the state
    # We'll take 8 bytes from each of the first 4 words
    for i in range(4):
        # Fix: Ensure the value is treated as an unsigned 64-bit integer
        word_value = state[i] & 0xFFFFFFFFFFFFFFFF  # Mask to 64 bits
        word_bytes = word_value.to_bytes(8, byteorder='big')
        digest += word_bytes
    
    return digest

def ascon_permutation(state, rounds):
    """Apply the ASCON permutation to the state for the specified number of rounds."""
    # Copy the state to avoid modifying the input
    state = state.copy()
    
    # Apply the specified number of rounds
    for r in range(12 - rounds, 12):
        # Add round constant
        state[2] ^= (0xf0 - r * 0x10 + r * 0x1)
        
        # Substitution layer (S-box)
        state = sbox(state)
        
        # Linear diffusion layer
        state = linear_layer(state)
        
        # Ensure state values stay within 64-bit range
        for i in range(5):
            state[i] &= 0xFFFFFFFFFFFFFFFF
    
    return state

def sbox(state):
    """Apply the ASCON S-box to the state."""
    # Extract the five 64-bit state words
    x0, x1, x2, x3, x4 = state
    
    # Apply the S-box to the entire state bitwise
    # This is equivalent to applying the 5-bit S-box to each column
    x0 ^= x4
    x2 ^= x1
    x4 ^= x3
    
    t0 = (~x0) & x1
    t1 = (~x1) & x2
    t2 = (~x2) & x3
    t3 = (~x3) & x4
    t4 = (~x4) & x0
    
    x0 ^= t1
    x1 ^= t2
    x2 ^= t3
    x3 ^= t4
    x4 ^= t0
    
    x1 ^= x0
    x0 ^= x4
    x3 ^= x2
    x2 = ~x2
    
    # Ensure all values stay within 64-bit range
    x0 &= 0xFFFFFFFFFFFFFFFF
    x1 &= 0xFFFFFFFFFFFFFFFF
    x2 &= 0xFFFFFFFFFFFFFFFF
    x3 &= 0xFFFFFFFFFFFFFFFF
    x4 &= 0xFFFFFFFFFFFFFFFF
    
    return [x0, x1, x2, x3, x4]

def linear_layer(state):
    """Apply the ASCON linear diffusion layer to the state."""
    # Extract state words
    x0, x1, x2, x3, x4 = state
    
    # Apply linear diffusion to each word
    x0 = x0 ^ right_rot(x0, 19) ^ right_rot(x0, 28)
    x1 = x1 ^ right_rot(x1, 61) ^ right_rot(x1, 39)
    x2 = x2 ^ right_rot(x2, 1) ^ right_rot(x2, 6)
    x3 = x3 ^ right_rot(x3, 10) ^ right_rot(x3, 17)
    x4 = x4 ^ right_rot(x4, 7) ^ right_rot(x4, 41)
    
    # Ensure all values stay within 64-bit range
    x0 &= 0xFFFFFFFFFFFFFFFF
    x1 &= 0xFFFFFFFFFFFFFFFF
    x2 &= 0xFFFFFFFFFFFFFFFF
    x3 &= 0xFFFFFFFFFFFFFFFF
    x4 &= 0xFFFFFFFFFFFFFFFF
    
    return [x0, x1, x2, x3, x4]

def right_rot(x, n):
    """Right rotate a 64-bit integer x by n bits."""
    # Ensure x is treated as a 64-bit value
    x &= 0xFFFFFFFFFFFFFFFF
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF