#!/usr/bin/env python3
"""Plot delivery-time CDFs for a directory of datapoint files.

Each datapoint file is a plain array of 32-byte little-endian records
(see src/datapoint.rs):

    timestamp_us: u64
    sender:       u32
    receiver:     u32
    serial:       u64
    delivery_us:  u32
    media_size:   u32

For every file in the directory one CDF curve is drawn, computed
directly from the sorted delivery times (no binning).  Only records
with delivery_us > 0 (receives) are considered.  The median of each
curve is marked and annotated with its x value.

Usage:
    ./plot_delivery_cdf.py DIR [-o output.png]
"""

import argparse
import sys
from pathlib import Path

import matplotlib
import numpy as np

DATAPOINT_DTYPE = np.dtype(
    [
        ("timestamp_us", "<u8"),
        ("sender", "<u4"),
        ("receiver", "<u4"),
        ("serial", "<u8"),
        ("delivery_us", "<u4"),
        ("media_size", "<u4"),
    ]
)
assert DATAPOINT_DTYPE.itemsize == 32


def load_delivery_ms(path: Path) -> np.ndarray:
    """Return sorted delivery times in milliseconds (receives only)."""
    records = np.fromfile(path, dtype=DATAPOINT_DTYPE)
    delivery_us = records["delivery_us"]
    delivery_us = delivery_us[delivery_us > 0]
    return np.sort(delivery_us).astype(np.float64) / 1000.0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot delivery-time CDFs for datapoint files."
    )
    parser.add_argument("directory", type=Path, help="directory of datapoint files")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the plot to this file instead of showing it",
    )
    args = parser.parse_args()

    if args.output:
        # Headless rendering when only writing to a file.
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    files = sorted(p for p in args.directory.iterdir() if p.is_file())
    if not files:
        sys.exit(f"no files found in {args.directory}")

    fig, ax = plt.subplots(figsize=(10, 6))

    for path in files:
        data = load_delivery_ms(path)
        if data.size == 0:
            print(f"{path.name}: no receives, skipping", file=sys.stderr)
            continue

        n = data.size
        # Empirical CDF straight from the sorted samples: the k-th
        # smallest sample (1-based) sits at probability k/n.
        cdf = np.arange(1, n + 1) / n
        (line,) = ax.plot(data, cdf, label=f"{path.name} (n={n})")

        # Median: the sample where the CDF first reaches 0.5.
        med_idx = int(np.searchsorted(cdf, 0.5))
        med_x = data[med_idx]
        ax.plot(
            med_x,
            cdf[med_idx],
            marker="o",
            color=line.get_color(),
            markersize=7,
            zorder=5,
        )
        ax.annotate(
            f"{med_x:.1f} ms",
            (med_x, cdf[med_idx]),
            textcoords="offset points",
            xytext=(8, -12),
            color=line.get_color(),
            fontsize=9,
        )

    ax.set_xlabel("delivery time (ms)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0, 1.02)
    ax.set_title("End-to-end delivery time CDF")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()

    if args.output:
        fig.savefig(args.output, dpi=150)
        print(f"wrote {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
