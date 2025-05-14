
import utils 

OUTPUT_FILENAME = "kats_vectors.txt"
NUM_TEST_CASES = 200

def generate_and_write_hashes():
    """
    Generates ASCON-Hash256 test vectors and writes them to a file.
    """
    current_msg_hex_list = [] # Stores parts of the hex message, e.g., ["00", "01", "02"]

    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
        for count in range(1, NUM_TEST_CASES + 1):
            msg_to_display_hex = ""

            if count == 1:
                # First message is empty
                msg_to_display_hex = ""
            elif count == 2:
                # Second message starts with '00'
                byte_val = 0
                current_msg_hex_list.append(f"{byte_val:02x}")
                msg_to_display_hex = "".join(current_msg_hex_list)
            else: # count > 2
                # Subsequent messages append the next byte
                byte_val = count - 2 # Byte value to append (0, 1, 2, ...)
                current_msg_hex_list.append(f"{byte_val:02x}")
                msg_to_display_hex = "".join(current_msg_hex_list)

            try:
                if msg_to_display_hex:
                    message_bytes = bytes.fromhex(msg_to_display_hex)
                else:
                    message_bytes = b"" # Empty bytes for an empty hex string
            except ValueError as ve:
                print(f"Error converting hex string '{msg_to_display_hex}' to bytes at Count {count}: {ve}")
                continue # Skip this test case if hex conversion fails

            # Calculate the ASCON-Hash256
            try:

                digest_bytes = utils.ascon_hash256(message_bytes)
                digest_hex_upper = digest_bytes.hex().upper()
            except Exception as e:
                print(f"Error hashing message for Count {count} (Msg='{msg_to_display_hex}'): {e}")
                digest_hex_upper = "ERROR_GENERATING_HASH"

            # Write to file in the specified format
            f.write(f"Count = {count}\n")
            f.write(f"Msg = {msg_to_display_hex}\n")
            f.write(f"MD = {digest_hex_upper}\n")
            if count < NUM_TEST_CASES:
                f.write("\n") 

    print(f"Successfully generated {NUM_TEST_CASES} test vectors in {OUTPUT_FILENAME}")

if __name__ == "__main__":
    try:
        _ = utils.zero_bytes(1) 
        generate_and_write_hashes()
    except AttributeError:
        print("Error: Could not access functions from utils.py.")
        print("Please ensure utils.py is in the same directory as this script.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")