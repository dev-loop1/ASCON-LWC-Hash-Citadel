
import time
import os
import sys
from statistics import mean, stdev # For averaging and standard deviation

# --- Importing Implementations ---

try:
    from utils import ascon_hash256 as optimized_ascon_hash256
    print("Successfully imported 'ascon_hash256' from local 'utils.py'.")
except ImportError:
    print("Error: Could not import 'ascon_hash256' from local 'utils.py'.")
    print("Please ensure 'utils.py' is in the same directory as this benchmark script.")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred while importing from 'utils.py': {e}")
    sys.exit(1)

# 2. Import ascon_hash from local ascon.py 
try:
    from ascon import ascon_hash as meichlseder_ascon_hash
    print("Successfully imported 'ascon_hash' from local 'ascon.py'.")
except ImportError:
    print("Error: Could not import 'ascon_hash' from local 'ascon.py'.")
    print("Please ensure 'ascon.py' (from meichlseder/pyascon) is in the same directory as this benchmark script.")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred while importing from 'ascon.py': {e}")
    sys.exit(1)


# --- Benchmark Configuration ---
# Data sizes to test (in bytes)
DATA_SIZES = {
    "1KB": 1 * 1024,
    "128KB": 128 * 1024,
    "1MB": 1 * 1024 * 1024,
    # "10MB": 10 * 1024 * 1024,
    # "50MB": 50 * 1024 * 1024,
}

# Number of iterations for each data size to average results
ITERATIONS = {
    "1KB": 5000,
    "128KB": 500,
    "1MB": 50,
    # "10MB": 5,
    # "50MB": 2,
}

# Number of warm-up iterations
WARMUP_ITERATIONS = 3

# --- Helper Functions ---

def generate_random_data(size_bytes: int) -> bytes:
    """Generates a block of random data of the specified size."""
    return os.urandom(size_bytes)

def benchmark_hash_function(hash_func, data: bytes, num_iterations: int, warmup_iterations: int, func_name: str, is_meichlseder_variant: bool = False):

    print(f"  Warming up {func_name}...")
    for _ in range(warmup_iterations):
        if is_meichlseder_variant:
            hash_func(data, variant="Ascon-Hash256", hashlength=32)
        else:
            hash_func(data)

    print(f"  Benchmarking {func_name} ({num_iterations} repetitions)...")
    
    timings_sec = [] # List to store individual timing results
    for i in range(num_iterations):
        start_time = time.perf_counter()
        if is_meichlseder_variant:
            digest = hash_func(data, variant="Ascon-Hash256", hashlength=32)
        else:
            digest = hash_func(data)
        end_time = time.perf_counter()
        timings_sec.append(end_time - start_time)
        
        if len(digest) != 32: # Ascon-Hash256 should produce 32 bytes
            print(f"    Warning: Unexpected digest length {len(digest)} from {func_name} on iteration {i+1}")

    # Calculate statistics
    avg_time_sec = mean(timings_sec) if timings_sec else 0
    std_dev_sec = stdev(timings_sec) if len(timings_sec) > 1 else 0
    
    average_time_ms = avg_time_sec * 1000
    stdev_time_ms = std_dev_sec * 1000

    # Calculate throughput
    # Total data processed in one iteration is len(data)
    # Throughput is (data_size_mb / avg_time_sec_per_iteration)
    data_size_mb = len(data) / (1024 * 1024)
    if avg_time_sec > 0:
        throughput_mb_s = data_size_mb / avg_time_sec
    else:
        throughput_mb_s = float('inf') # Avoid division by zero

    return average_time_ms, stdev_time_ms, throughput_mb_s

# --- Main Benchmark Execution ---

if __name__ == "__main__":
    print("Starting Ascon-Hash256 Benchmark...\n")
    print("Comparing implementations:")
    print("  1. Optimized Ascon-Hash256 (from local 'utils.py')")
    print("  2. Reference Ascon-Hash256 (from local 'ascon.py' - meichlseder/pyascon)\n")
    print(f"Warm-up iterations per function: {WARMUP_ITERATIONS}")

    results_summary = {} # Dictionary to store results for final summary

    # Iterate over each defined data size for benchmarking
    for size_label, data_size_bytes in DATA_SIZES.items():
        data_mb_label = data_size_bytes / (1024*1024) # For display
        print(f"\n--- Testing with Data Size: {size_label} ({data_mb_label:.2f} MB) ---")
        
        test_data_current = generate_random_data(data_size_bytes)
        num_iter_current = ITERATIONS.get(size_label, 10) 

        results_summary[size_label] = {}

        # 1. Benchmark Optimized Ascon-Hash256
        try:
            avg_ms, stdev_ms, throughput_mbs = benchmark_hash_function(
                optimized_ascon_hash256,
                test_data_current,
                num_iter_current,
                WARMUP_ITERATIONS,
                "Optimized (utils.py)"
            )
            results_summary[size_label]["optimized"] = {
                "avg_time_ms": avg_ms,
                "stdev_ms": stdev_ms,
                "throughput_mb_s": throughput_mbs,
                "iterations": num_iter_current
            }
        except Exception as e:
            print(f"    Error benchmarking Optimized (utils.py): {e}")
            results_summary[size_label]["optimized"] = {"error": str(e)}

        # 2. Benchmark standard Ascon-Hash256
        try:
            avg_ms, stdev_ms, throughput_mbs = benchmark_hash_function(
                meichlseder_ascon_hash,
                test_data_current,
                num_iter_current,
                WARMUP_ITERATIONS,
                "Reference (ascon.py)",
                is_meichlseder_variant=True 
            )
            results_summary[size_label]["reference"] = {
                "avg_time_ms": avg_ms,
                "stdev_ms": stdev_ms,
                "throughput_mb_s": throughput_mbs,
                "iterations": num_iter_current
            }
        except Exception as e:
            print(f"    Error benchmarking Reference (ascon.py): {e}")
            results_summary[size_label]["reference"] = {"error": str(e)}
        
        print("-" * (len(f"--- Testing with Data Size: {size_label} ({data_mb_label:.2f} MB) ---") +0))
    
    # --- Summary of Results ---
    print("\n\n--- Benchmark Summary ---")
    print(f"{'Data Size':<10} | {'Implementation':<25} | {'Avg. Time (ms)':<18} | {'Std. Dev (ms)':<18} | {'Throughput (MB/s)':<20}")
    print("-" * 100)

    for size_label, res_for_size in results_summary.items():
        data_mb_val = DATA_SIZES[size_label] / (1024*1024)
        
        # Optimized Version Results
        if "optimized" in res_for_size:
            opt_res = res_for_size["optimized"]
            if "error" in opt_res:
                print(f"{size_label:<10} | {'Optimized (utils.py)':<25} | {'Error':<18} | {'N/A':<18} | {'N/A':<20}")
                print(f"{'':<10} | {f'  Error: {opt_res["error"][:50]}...':<79}")

            else:
                print(f"{size_label:<10} | {'Optimized (utils.py)':<25} | {opt_res['avg_time_ms']:<18.3f} | {opt_res['stdev_ms']:<18.3f} | {opt_res['throughput_mb_s']:<20.2f}")

        # Reference Version Results
        if "reference" in res_for_size:
            ref_res = res_for_size["reference"]
            if "error" in ref_res:
                print(f"{size_label:<10} | {'Reference (ascon.py)':<25} | {'Error':<18} | {'N/A':<18} | {'N/A':<20}")
                print(f"{'':<10} | {f'  Error: {ref_res["error"][:50]}...':<79}")
            else:
                print(f"{size_label:<10} | {'Reference (ascon.py)':<25} | {ref_res['avg_time_ms']:<18.3f} | {ref_res['stdev_ms']:<18.3f} | {ref_res['throughput_mb_s']:<20.2f}")
        print("-" * 100)
    
    print("\nBenchmark Complete.")
