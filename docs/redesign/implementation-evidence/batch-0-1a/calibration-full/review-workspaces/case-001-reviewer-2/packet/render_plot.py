#!/usr/bin/env python3
"""Reproduce the delivered chart from the source CSV; write only to --output-dir."""
import argparse
import csv
import os
from pathlib import Path

DIVISOR = 1000.0
COLOR = "#2864A8"

def draw_chart(time_values, concentration_values, output_path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    with plt.rc_context({"font.family": "DejaVu Sans", "font.size": 13,
                         "axes.titleweight": "bold", "axes.labelsize": 14,
                         "savefig.facecolor": "white"}):
        fig, ax = plt.subplots(figsize=(10, 6.5), dpi=160)
        fig.subplots_adjust(left=0.14, right=0.95, bottom=0.17, top=0.83)
        top = max(concentration_values)
        ax.fill_between(time_values, concentration_values, color=COLOR, alpha=0.09)
        ax.plot(time_values, concentration_values, color=COLOR, linewidth=3,
                marker="o", markersize=8, markerfacecolor="white", markeredgewidth=2.5)
        ax.set_title("Concentration over time", loc="left", fontsize=22, pad=23)
        ax.set_xlabel("Time (s)", labelpad=12)
        ax.set_ylabel("Concentration (g/L)", labelpad=16)
        ax.set_xticks(time_values)
        ax.set_yticks(concentration_values)
        ax.yaxis.set_major_formatter(FuncFormatter(lambda value, pos: f"{value:g}"))
        ax.set_xlim(-1.5, 31.5)
        ax.set_ylim(-top * 0.07, top * 1.18)
        ax.set_axisbelow(True)
        ax.grid(axis="y", color="#DCE2E8", linewidth=0.8)
        ax.spines[["top", "right"]].set_visible(False)
        ax.spines[["bottom", "left"]].set_color("#AAB4BF")
        ax.tick_params(colors="#344250", length=0, pad=10)
        for x, y in zip(time_values, concentration_values):
            ax.annotate(f"{y:g}", (x, y), xytext=(0, 12), textcoords="offset points",
                        ha="center", color=COLOR, fontsize=12, fontweight="bold")
        fig.savefig(output_path, dpi=160,
                    metadata={"Software": "Matplotlib deterministic manual fixture"})
        plt.close(fig)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source_dir = Path(__file__).resolve().parent
    out = args.output_dir.resolve()
    if out == source_dir:
        parser.error("The review packet is read-only; use a different output directory.")
    out.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(out / ".matplotlib-cache"))
    with (source_dir / "source.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    times = [float(row["time_s"]) for row in rows]
    values = [float(row["concentration_mg_L"]) / DIVISOR for row in rows]
    with (out / "plot-data.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time_s", "concentration_g_L"])
        writer.writerows(zip(times, values))
    draw_chart(times, values, out / "chart.png")

if __name__ == "__main__":
    main()
