import yaml
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse
from scipy import stats


def load_data(yaml_path):
    with open(yaml_path, 'r') as f:
        data = yaml.safe_load(f)
    return data['commandExecutionStats']


def process_data(raw_data):
    df = pd.DataFrame(raw_data)

    # Convert to numerical values
    for col in ['RTT', 'repRxTime', 'overhead', 'total']:
        df[col] = pd.to_numeric(df[col].str.replace('μs', '').replace('undefined', np.nan), errors='coerce')

    return df


def plot_metrics(df, window_size=5, use_ema=False):
    plt.figure(figsize=(12, 6))
    colors = {'RTT': 'blue', 'repRxTime': 'green', 'overhead': 'red', 'total': 'purple'}

    for metric in df.columns:
        # Moving average/EMA
        if use_ema:
            ma = df[metric].ewm(span=window_size).mean()
        else:
            ma = df[metric].rolling(window_size, center=True).mean()

        plt.plot(df.index, ma, linestyle='-', color=colors.get(metric, 'black'), label=f'{metric} MA ({window_size})')

        # Mark timeouts for RTT (values > 20,000,000 μs)
        if metric == 'RTT':
            timeout_indices = df.index[df[metric] > 20000000]
            plt.scatter(timeout_indices, df[metric][timeout_indices], color='black', marker='x', label='RTT Timeout', zorder=3)

    plt.title('Latency Metrics Moving Averages')
    plt.xlabel('Request Sequence')
    plt.ylabel('Time (μs)')
    # plt.yscale('log')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True)
    plt.tight_layout()
    plt.show()


def main():
    parser = argparse.ArgumentParser(description='Latency Metrics Analyzer')
    parser.add_argument('input', help='Input YAML file path')
    parser.add_argument('-w', '--window', type=int, default=5, help='Window size for moving average')
    parser.add_argument('--ema', action='store_true', help='Use Exponential Moving Average instead of simple MA')

    args = parser.parse_args()

    # Load and process data
    raw_data = load_data(args.input)
    df = process_data(raw_data)

    # Plot results
    plot_metrics(df, args.window, args.ema)


if __name__ == '__main__':
    main()
