import numpy as np
from crypto_utils import generate_ecc_keypair, derive_shared_key
import time

class TimingAttack:
    def __init__(self, num_samples=1000):
        self.num_samples = num_samples
        self.target_priv, self.target_pub = generate_ecc_keypair()
        self.recovered_bits = []
        
    def measure_operation(self, test_key):
        """Measure time for ECDH operation"""
        start = time.perf_counter()
        derive_shared_key(test_key, self.target_pub)
        end = time.perf_counter()
        return (end - start) * 1000  # ms
    
    def attack_single_bit(self, bit_position):
        """Attack to recover a single bit"""
        timings_0 = []  # timings when we guess bit is 0
        timings_1 = []  # timings when we guess bit is 1
        
        for _ in range(self.num_samples):
            test_priv, _ = generate_ecc_keypair()
            timing = self.measure_operation(test_priv)
            
            # Check the bit we're interested in
            bit = (test_priv.private_numbers().private_value >> bit_position) & 1
            if bit == 0:
                timings_0.append(timing)
            else:
                timings_1.append(timing)
        
        # Compare timing distributions
        mean_0 = np.mean(timings_0)
        mean_1 = np.mean(timings_1)
        
        # Guess the bit based on timing difference
        return 1 if mean_1 < mean_0 else 0
    
    def perform_attack(self, num_bits=8):
        """Attempt to recover multiple bits of the private key"""
        print("\nAttempting to recover private key bits...")
        recovered_bits = []
        
        for bit_pos in range(num_bits):
            recovered_bit = self.attack_single_bit(bit_pos)
            recovered_bits.append(recovered_bit)
            print(f"Recovered bit {bit_pos}: {recovered_bit}")
        
        # Verify recovered bits
        actual_bits = [(self.target_priv.private_numbers().private_value >> i) & 1 
                      for i in range(num_bits)]
        
        correct = sum(1 for a, b in zip(actual_bits, recovered_bits) if a == b)
        accuracy = (correct / num_bits) * 100
        
        print(f"\nAttack Results:")
        print(f"Actual bits:    {actual_bits}")
        print(f"Recovered bits: {recovered_bits}")
        print(f"Accuracy: {accuracy:.1f}%")
        
        return recovered_bits, accuracy

def run_attack_demo():
    """Run a demonstration of the timing attack"""
    print("=== Starting Timing Attack Demonstration ===")
    
    attack = TimingAttack(num_samples=1000)
    recovered_bits, accuracy = attack.perform_attack(num_bits=8)
    
    if accuracy > 60:
        print("\nAttack successful! Demonstrated vulnerability to timing analysis.")
    else:
        print("\nAttack unsuccessful. Implementation may be resistant to timing analysis.")
    
    return recovered_bits, accuracy

if __name__ == "__main__":
    run_attack_demo() 