import statistics
import time
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats
from crypto_utils import generate_ecc_keypair, derive_shared_key
import os
from scipy.stats import kstest

# Create plots directory if it doesn't exist
PLOTS_DIR = os.path.join(os.path.dirname(__file__), 'plots')
os.makedirs(PLOTS_DIR, exist_ok=True)

def measure_ecc_keygen_time(num_samples=100):
    """Measure time taken for ECC key generation"""
    times = []
    for _ in range(num_samples):
        start = time.perf_counter()  # More precise than time.time()
        generate_ecc_keypair()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to milliseconds
    return times

def measure_ecdh_time(num_samples=100):
    """Measure time taken for ECDH key exchange"""
    times = []
    # Generate fixed keys for consistency
    priv_a, pub_a = generate_ecc_keypair()
    priv_b, pub_b = generate_ecc_keypair()
    
    for _ in range(num_samples):
        start = time.perf_counter()
        derive_shared_key(priv_a, pub_b)  # Measure ECDH operation
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to milliseconds
    return times

def plot_timing_distribution(times, operation_name):
    """Create timing distribution plots and save to files"""
    # Create a figure with two subplots side by side
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Histogram
    ax1.hist(times, bins=30, edgecolor='black')
    ax1.set_title(f'Histogram for {operation_name}')
    ax1.set_xlabel('Time (milliseconds)')
    ax1.set_ylabel('Frequency')
    ax1.grid(True, alpha=0.3)
    
    # Scatter plot
    ax2.scatter(range(len(times)), times, alpha=0.5, s=20)
    ax2.set_title(f'Scatter Plot for {operation_name}')
    ax2.set_xlabel('Operation Sequence')
    ax2.set_ylabel('Time (milliseconds)')
    ax2.grid(True, alpha=0.3)
    
    # Add statistical annotations
    mean_time = np.mean(times)
    std_time = np.std(times)
    
    # Add mean line to both plots
    ax1.axvline(mean_time, color='r', linestyle='dashed', linewidth=2, label=f'Mean: {mean_time:.2f}ms')
    ax2.axhline(mean_time, color='r', linestyle='dashed', linewidth=2, label=f'Mean: {mean_time:.2f}ms')
    
    # Add text annotations
    stats_text = f'Mean: {mean_time:.2f}ms\nStd Dev: {std_time:.2f}ms'
    fig.text(0.98, 0.95, stats_text, 
             bbox=dict(facecolor='white', alpha=0.8),
             horizontalalignment='right')
    
    # Adjust layout
    plt.tight_layout()
    
    # Save plot to file
    filename = f"{operation_name.lower().replace(' ', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.png"
    filepath = os.path.join(PLOTS_DIR, filename)
    plt.savefig(filepath, bbox_inches='tight', dpi=300)
    plt.close()  # Close the figure to free memory
    
    print(f"Plot saved to: {filepath}")

def save_timing_data(times, operation_name):
    """Save timing measurements to a CSV file"""
    filename = f"{operation_name.lower().replace(' ', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(PLOTS_DIR, filename)
    
    with open(filepath, 'w') as f:
        f.write("measurement_ms\n")
        for t in times:
            f.write(f"{t:.6f}\n")
    
    print(f"Data saved to: {filepath}")

def run_timing_analysis():
    """Run comprehensive timing analysis"""
    print("\n=== ECC Operations Timing Analysis ===\n")
    
    # Test key generation timing
    print("Measuring ECC Key Generation timing...")
    keygen_times = measure_ecc_keygen_time()
    print(f"Average key generation time: {np.mean(keygen_times):.2f}ms")
    print(f"Standard deviation: {np.std(keygen_times):.2f}ms")
    plot_timing_distribution(keygen_times, "ECC Key Generation")
    save_timing_data(keygen_times, "ECC Key Generation")
    
    # Test ECDH timing
    print("\nMeasuring ECDH Key Exchange timing...")
    ecdh_times = measure_ecdh_time()
    print(f"Average ECDH time: {np.mean(ecdh_times):.2f}ms")
    print(f"Standard deviation: {np.std(ecdh_times):.2f}ms")
    plot_timing_distribution(ecdh_times, "ECDH Key Exchange")
    save_timing_data(ecdh_times, "ECDH Key Exchange")
    
    # Additional analysis
    print("\nTiming Variations Analysis:")
    print(f"Key Generation timing range: {max(keygen_times) - min(keygen_times):.2f}ms")
    print(f"ECDH timing range: {max(ecdh_times) - min(ecdh_times):.2f}ms")

def simulate_timing_attack():
    """Simulate a timing attack on ECDH operations"""
    # Generate target key pair
    target_priv, target_pub = generate_ecc_keypair()
    
    # Collect timing data for different key bits
    timing_data = {'0': [], '1': []}
    num_samples = 1000
    
    for _ in range(num_samples):
        # Try operations with known key bits
        test_priv, test_pub = generate_ecc_keypair()
        
        start = time.perf_counter()
        derive_shared_key(test_priv, target_pub)
        end = time.perf_counter()
        
        # Classify timing based on first bit of private key
        key_bit = '1' if test_priv.private_numbers().private_value & 1 else '0'
        timing_data[key_bit].append((end - start) * 1000)
    
    return timing_data

def simulate_power_analysis():
    """Simulate power consumption during operations"""
    power_traces = []
    
    def mock_power_measurement(operation):
        # Simulate power consumption based on operation complexity
        base_power = 100  # milliwatts
        noise = np.random.normal(0, 5)
        return base_power + len(str(operation)) + noise
    
    # Collect power traces during key operations
    priv, pub = generate_ecc_keypair()
    for _ in range(100):
        trace = []
        for bit in bin(priv.private_numbers().private_value)[2:]:
            if bit == '1':
                trace.append(mock_power_measurement("multiply"))
            else:
                trace.append(mock_power_measurement("square"))
        power_traces.append(trace)
    
    return power_traces

def simulate_cache_timing():
    """Simulate cache-based timing attacks"""
    cache_hits = []
    cache_misses = []
    
    def measure_with_cache_state(data_in_cache):
        start = time.perf_counter()
        if data_in_cache:
            # Simulate cache hit
            time.sleep(0.0001)  # 0.1ms
        else:
            # Simulate cache miss
            time.sleep(0.001)   # 1ms
        end = time.perf_counter()
        return (end - start) * 1000
    
    # Collect timing data for cache hits/misses
    for _ in range(100):
        cache_hits.append(measure_with_cache_state(True))
        cache_misses.append(measure_with_cache_state(False))
    
    return cache_hits, cache_misses

def analyze_timing_patterns(times):
    """Perform detailed statistical analysis of timing data"""
    analysis = {
        'mean': np.mean(times),
        'std': np.std(times),
        'median': np.median(times),
        'skewness': stats.skew(times),
        'kurtosis': stats.kurtosis(times),
        'outliers': identify_outliers(times)
    }
    
    # Test for randomness
    _, p_value = kstest(times, 'norm')
    analysis['normally_distributed'] = p_value > 0.05
    
    return analysis

def plot_detailed_analysis():
    """Create detailed plots for each type of side-channel attack"""
    
    # 1. Timing Analysis
    timing_data = simulate_timing_attack()
    fig1, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
    
    # Histogram
    ax1.hist(timing_data['0'], bins=30, alpha=0.5, label='Bit 0')
    ax1.hist(timing_data['1'], bins=30, alpha=0.5, label='Bit 1')
    ax1.set_title('Timing Distribution by Key Bit')
    ax1.set_xlabel('Time (ms)')
    ax1.legend()
    
    # Cumulative Distribution
    ax2.hist(timing_data['0'], bins=30, cumulative=True, density=True, 
             histtype='step', label='Bit 0', alpha=0.8)
    ax2.hist(timing_data['1'], bins=30, cumulative=True, density=True,
             histtype='step', label='Bit 1', alpha=0.8)
    ax2.set_title('Cumulative Timing Distribution')
    ax2.legend()
    
    # Statistical Analysis
    stats = {
        'Bit 0': {
            'mean': np.mean(timing_data['0']),
            'std': np.std(timing_data['0']),
            'median': np.median(timing_data['0'])
        },
        'Bit 1': {
            'mean': np.mean(timing_data['1']),
            'std': np.std(timing_data['1']),
            'median': np.median(timing_data['1'])
        }
    }
    ax3.text(0.1, 0.5, f"Statistics:\n\n"
             f"Bit 0:\n"
             f"Mean: {stats['Bit 0']['mean']:.3f}ms\n"
             f"Std: {stats['Bit 0']['std']:.3f}ms\n"
             f"Median: {stats['Bit 0']['median']:.3f}ms\n\n"
             f"Bit 1:\n"
             f"Mean: {stats['Bit 1']['mean']:.3f}ms\n"
             f"Std: {stats['Bit 1']['std']:.3f}ms\n"
             f"Median: {stats['Bit 1']['median']:.3f}ms",
             fontfamily='monospace')
    ax3.axis('off')
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'timing_analysis_detailed.png'))
    plt.close()
    
    # 2. Power Analysis
    power_traces = simulate_power_analysis()
    fig2, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
    
    # Multiple traces overlay
    for i in range(min(10, len(power_traces))):
        ax1.plot(power_traces[i], alpha=0.3, label=f'Trace {i+1}' if i < 3 else '')
    ax1.set_title('Multiple Power Traces Overlay')
    ax1.set_xlabel('Operation Sequence')
    ax1.set_ylabel('Power (mW)')
    ax1.legend()
    
    # Average trace with variance
    mean_trace = np.mean(power_traces, axis=0)
    std_trace = np.std(power_traces, axis=0)
    ax2.plot(mean_trace, 'b-', label='Mean Power')
    ax2.fill_between(range(len(mean_trace)), 
                     mean_trace - std_trace,
                     mean_trace + std_trace,
                     alpha=0.3, label='±1 Std Dev')
    ax2.set_title('Average Power Trace with Variance')
    ax2.set_xlabel('Operation Sequence')
    ax2.set_ylabel('Power (mW)')
    ax2.legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'power_analysis_detailed.png'))
    plt.close()
    
    # 3. Cache Analysis
    cache_hits, cache_misses = simulate_cache_timing()
    fig3, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Violin plot
    ax1.violinplot([cache_hits, cache_misses], showmeans=True)
    ax1.set_xticks([1, 2])
    ax1.set_xticklabels(['Cache Hits', 'Cache Misses'])
    ax1.set_title('Cache Timing Distribution (Violin Plot)')
    ax1.set_ylabel('Time (ms)')
    
    # Time series with moving average
    window = 10
    hit_ma = np.convolve(cache_hits, np.ones(window)/window, mode='valid')
    miss_ma = np.convolve(cache_misses, np.ones(window)/window, mode='valid')
    
    ax2.plot(cache_hits, 'b.', alpha=0.3, label='Cache Hits')
    ax2.plot(cache_misses, 'r.', alpha=0.3, label='Cache Misses')
    ax2.plot(range(window-1, len(cache_hits)), hit_ma, 'b-', label='Hits Moving Avg')
    ax2.plot(range(window-1, len(cache_misses)), miss_ma, 'r-', label='Misses Moving Avg')
    ax2.set_title('Cache Timing Patterns')
    ax2.set_xlabel('Operation Sequence')
    ax2.set_ylabel('Time (ms)')
    ax2.legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'cache_analysis_detailed.png'))
    plt.close()

def create_summary_plot():
    """Create a comprehensive summary plot for presentation"""
    fig = plt.figure(figsize=(15, 10))
    
    # 1. Timing Analysis (2x2 grid)
    gs = fig.add_gridspec(2, 2, hspace=0.3, wspace=0.3)
    
    # Basic timing distributions
    ax1 = fig.add_subplot(gs[0, 0])
    keygen_times = measure_ecc_keygen_time()
    ax1.hist(keygen_times, bins=30, alpha=0.7)
    ax1.set_title('Key Generation Timing')
    ax1.set_xlabel('Time (ms)')
    
    # ECDH timing
    ax2 = fig.add_subplot(gs[0, 1])
    ecdh_times = measure_ecdh_time()
    ax2.hist(ecdh_times, bins=30, alpha=0.7)
    ax2.set_title('ECDH Operation Timing')
    ax2.set_xlabel('Time (ms)')
    
    # Power analysis
    ax3 = fig.add_subplot(gs[1, 0])
    power_traces = simulate_power_analysis()
    mean_trace = np.mean(power_traces, axis=0)
    ax3.plot(mean_trace, label='Average Power')
    ax3.set_title('Power Analysis')
    ax3.set_xlabel('Operation Sequence')
    ax3.set_ylabel('Power (mW)')
    
    # Cache timing
    ax4 = fig.add_subplot(gs[1, 1])
    cache_hits, cache_misses = simulate_cache_timing()
    ax4.boxplot([cache_hits, cache_misses], labels=['Cache Hits', 'Cache Misses'])
    ax4.set_title('Cache Timing Analysis')
    ax4.set_ylabel('Time (ms)')
    
    # Add overall title
    fig.suptitle('Side-Channel Analysis Summary', fontsize=16, y=1.02)
    
    # Save plot
    plt.savefig(os.path.join(PLOTS_DIR, 'side_channel_summary.png'), 
                bbox_inches='tight', dpi=300)
    plt.close()

def run_all_analyses():
    """Run all side-channel analyses with detailed plots"""
    print("\n=== Running Detailed Side-Channel Analysis ===\n")
    
    # Run basic timing analysis
    run_timing_analysis()
    
    # Generate detailed plots
    print("\nGenerating detailed analysis plots...")
    plot_detailed_analysis()
    print("Detailed analysis plots saved in the 'plots' directory")
    create_summary_plot()

def identify_outliers(data, threshold=2):
    """
    Identify outliers in the timing data using z-score method.
    Args:
        data: List of timing measurements
        threshold: Number of standard deviations to consider as outlier (default: 2)
    Returns:
        List of indices where outliers occur
    """
    mean = np.mean(data)
    std = np.std(data)
    z_scores = [(x - mean) / std for x in data]
    return [i for i, z in enumerate(z_scores) if abs(z) > threshold]

if __name__ == "__main__":
    run_all_analyses() 