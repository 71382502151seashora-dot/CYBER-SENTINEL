
from pathlib import Path
import re
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "Dataset"
GRAPH_DIR = ROOT / "Graphs"
OUTPUT_DIR = ROOT / "outputs"
REPORT_DIR = ROOT / "Final_Report"

for folder in (GRAPH_DIR, OUTPUT_DIR, REPORT_DIR):
    folder.mkdir(parents=True, exist_ok=True)


# ==============================
# PREMIUM DARK NEON THEME
# ==============================

BG_COLOR = "#100B1D"
CARD_COLOR = "#1B1230"
TEXT_COLOR = "#F4EEFF"
MUTED_COLOR = "#B9A8D8"
GRID_COLOR = "#49365F"

NEON_PALETTE = [
    "#B66CFF", "#7C5CFF", "#35D6FF",
    "#FF63C3", "#65F0C1", "#FFB86B",
    "#8B9CFF", "#F47CFF", "#7EE7FF",
    "#C6A0FF"
]


def style_chart(ax, title, xlabel="", ylabel=""):
    ax.set_facecolor(CARD_COLOR)
    ax.figure.patch.set_facecolor(BG_COLOR)

    ax.set_title(
        title,
        color=TEXT_COLOR,
        fontsize=14,
        fontweight="bold",
        pad=16
    )

    ax.set_xlabel(xlabel, color=MUTED_COLOR, labelpad=9)
    ax.set_ylabel(ylabel, color=MUTED_COLOR, labelpad=9)

    ax.tick_params(colors=MUTED_COLOR, labelsize=9)

    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)

    ax.grid(
        axis="y",
        color=GRID_COLOR,
        linestyle="--",
        linewidth=0.7,
        alpha=0.55
    )

    ax.set_axisbelow(True)


def save_styled_figure(filename):
    plt.tight_layout(pad=2)

    plt.savefig(
        GRAPH_DIR / filename,
        dpi=180,
        facecolor=BG_COLOR,
        bbox_inches="tight"
    )

    plt.close()


# ==============================
# COLUMN ALIASES
# ==============================

ALIASES = {
    "source_ip": [
        "source ip", "src ip", "source ip address",
        "src_ip", "source"
    ],
    "destination_ip": [
        "destination ip", "dst ip",
        "destination ip address", "dst_ip", "destination"
    ],
    "source_port": [
        "source port", "src port",
        "source_port", "src_port"
    ],
    "destination_port": [
        "destination port", "dst port",
        "destination_port", "dst_port"
    ],
    "protocol": ["protocol", "proto"],
    "timestamp": [
        "timestamp", "time stamp",
        "date time", "datetime", "flow start"
    ],
    "packet_count": [
        "packet count", "total packets",
        "total fwd packets", "total forward packets", "packets"
    ],
    "flow_duration": [
        "flow duration", "duration", "flow_duration"
    ],
    "byte_count": [
        "byte count", "total bytes",
        "total length of fwd packets", "bytes", "flow bytes"
    ],
    "label": [
        "label", "attack", "attack type",
        "traffic label", "class", "category"
    ]
}


def clean_col_name(name):
    return re.sub(
        r"\s+",
        " ",
        str(name).replace("_", " ").strip()
    ).lower()


def resolve_columns(df):
    normalized = {
        clean_col_name(c): c for c in df.columns
    }

    mapping = {}

    for standard, aliases in ALIASES.items():
        for alias in aliases:
            key = clean_col_name(alias)

            if key in normalized:
                mapping[standard] = normalized[key]
                break

    if "packet_count" not in mapping:
        fwd = (
            normalized.get("total fwd packets")
            or normalized.get("total forward packets")
        )

        if fwd:
            mapping["packet_count"] = fwd

    if "byte_count" not in mapping:
        fwd = normalized.get("total length of fwd packets")

        if fwd:
            mapping["byte_count"] = fwd

    return mapping


# ==============================
# LOAD DATASET
# ==============================

def load_data(csv_path=None):

    path = (
        Path(csv_path)
        if csv_path
        else DATA_DIR / "cybersecurity_data.csv"
    )

    if not path.exists():

        demo = DATA_DIR / "demo_cybersecurity_data.csv"

        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            f"Download a public CSV and save it as {path.name}. "
            f"For a test only, copy {demo.name} to {path.name}."
        )

    return pd.read_csv(
        path,
        encoding="utf-8-sig",
        low_memory=False
    )


def prepare_data(df):

    data = df.copy()

    data.columns = [
        str(c).strip() for c in data.columns
    ]

    mapping = resolve_columns(data)

    for key in [
        "source_port",
        "destination_port",
        "packet_count",
        "flow_duration",
        "byte_count"
    ]:

        if key in mapping:
            data[mapping[key]] = pd.to_numeric(
                data[mapping[key]],
                errors="coerce"
            )

    if "timestamp" in mapping:
        data[mapping["timestamp"]] = pd.to_datetime(
            data[mapping["timestamp"]],
            errors="coerce"
        )

    return data, mapping


# ==============================
# PROTOCOL ANALYSIS
# ==============================

def protocol_series(df, mapping):

    if "protocol" not in mapping:
        return None

    s = df[mapping["protocol"]].astype(str).str.strip()

    names = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "tcp": "TCP",
        "udp": "UDP",
        "icmp": "ICMP"
    }

    return s.map(
        lambda x: names.get(x.lower(), x)
    )


# ==============================
# RULE BASED THREAT SCREENING
# ==============================

def create_rule_flags(df, mapping):

    flags = pd.Series(False, index=df.index)

    reasons = pd.Series(
        "",
        index=df.index,
        dtype="object"
    )

    rules_used = []

    for key, description in [
        (
            "packet_count",
            "packet count above the dataset 99th percentile"
        ),
        (
            "byte_count",
            "byte count above the dataset 99th percentile"
        ),
        (
            "flow_duration",
            "very short flow duration (at/below 1st percentile)"
        )
    ]:

        if key not in mapping:
            continue

        col = mapping[key]

        vals = pd.to_numeric(
            df[col],
            errors="coerce"
        )

        valid = vals.dropna()

        if len(valid) < 5:
            continue

        if key in ("packet_count", "byte_count"):

            threshold = valid.quantile(0.99)
            current = vals > threshold

        else:

            threshold = valid.quantile(0.01)
            current = (vals <= threshold) & (vals > 0)

        flags |= current.fillna(False)

        reasons.loc[current.fillna(False)] = (
            reasons.loc[current.fillna(False)].apply(
                lambda old:
                (old + "; " if old else "") + description
            )
        )

        rules_used.append(
            f"{description}: threshold={threshold:.4g}"
        )

    return flags, reasons, rules_used


# ==============================
# STYLED BAR CHART
# ==============================

def save_bar(
    series,
    title,
    xlabel,
    ylabel,
    filename,
    horizontal=False
):

    if series is None or len(series) == 0:
        return False

    values = (
        series.sort_values(ascending=True)
        if horizontal
        else series
    )

    fig, ax = plt.subplots(figsize=(10, 5.4))

    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(CARD_COLOR)

    colors = [
        NEON_PALETTE[i % len(NEON_PALETTE)]
        for i in range(len(values))
    ]

    if horizontal:

        bars = ax.barh(
            values.index.astype(str),
            values.values,
            color=colors,
            height=0.62,
            edgecolor="#D8B5FF",
            linewidth=0.45
        )

        ax.grid(
            axis="x",
            color=GRID_COLOR,
            linestyle="--",
            alpha=0.45
        )

        ax.grid(axis="y", visible=False)

        for bar, value in zip(bars, values.values):

            ax.text(
                bar.get_width(),
                bar.get_y() + bar.get_height() / 2,
                f"  {value:,.0f}",
                va="center",
                ha="left",
                color=TEXT_COLOR,
                fontsize=9
            )

    else:

        bars = ax.bar(
            values.index.astype(str),
            values.values,
            color=colors,
            width=0.62,
            edgecolor="#D8B5FF",
            linewidth=0.45
        )

        ax.grid(
            axis="y",
            color=GRID_COLOR,
            linestyle="--",
            alpha=0.45
        )

        ax.grid(axis="x", visible=False)

        for bar, value in zip(bars, values.values):

            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{value:,.0f}",
                ha="center",
                va="bottom",
                color=TEXT_COLOR,
                fontsize=9
            )

    style_chart(ax, title, xlabel, ylabel)

    ax.margins(x=0.12, y=0.16)

    save_styled_figure(filename)

    return True


# ==============================
# MAIN ANALYSIS
# ==============================

def run_analysis(df, mapping, label=""):

    cleaned = df.drop_duplicates().copy()

    cleaned.to_csv(
        OUTPUT_DIR / "cleaned_data.csv",
        index=False
    )

    summary_lines = []

    summary_lines += [
        "CYBERSECURITY THREAT DETECTION AND ANALYSIS USING PYTHON",
        "=" * 58,
        f"Dataset: {label or 'cybersecurity_data.csv'}",
        f"Rows after duplicate removal: {len(cleaned):,}",
        f"Columns: {cleaned.shape[1]}",
        f"Duplicate rows removed: {len(df) - len(cleaned):,}",
        f"Missing values (all cells): {int(cleaned.isna().sum().sum()):,}",
        "",
        "AVAILABLE FIELD MAPPING",
        str(mapping),
        ""
    ]

    # PROTOCOL DISTRIBUTION

    protocols = protocol_series(cleaned, mapping)

    if protocols is not None:

        counts = protocols.value_counts().head(20)

        counts.to_csv(
            OUTPUT_DIR / "protocol_summary.csv",
            header=["records"]
        )

        save_bar(
            counts,
            "Protocol Distribution",
            "Protocol",
            "Number of records",
            "01_protocol_distribution.png"
        )

        summary_lines += [
            "Protocol distribution:",
            counts.to_string(),
            ""
        ]

    # SOURCE IP ANALYSIS

    if "source_ip" in mapping:

        counts = (
            cleaned[mapping["source_ip"]]
            .astype(str)
            .value_counts()
            .head(10)
        )

        counts.to_csv(
            OUTPUT_DIR / "top_source_ips.csv",
            header=["records"]
        )

        save_bar(
            counts,
            "Top 10 Source IP Addresses",
            "Source IP",
            "Number of records",
            "02_top_source_ips.png",
            horizontal=True
        )

        summary_lines += [
            "Top source IP addresses:",
            counts.to_string(),
            ""
        ]

    # DESTINATION PORT ANALYSIS

    if "destination_port" in mapping:

        counts = (
            cleaned[mapping["destination_port"]]
            .dropna()
            .astype(str)
            .value_counts()
            .head(10)
        )

        counts.to_csv(
            OUTPUT_DIR / "top_destination_ports.csv",
            header=["records"]
        )

        save_bar(
            counts,
            "Top 10 Destination Ports",
            "Destination port",
            "Number of records",
            "03_top_destination_ports.png",
            horizontal=True
        )

        summary_lines += [
            "Top destination ports:",
            counts.to_string(),
            ""
        ]

    # TRAFFIC VOLUME HISTOGRAM

    volume_col = (
        mapping.get("byte_count")
        or mapping.get("packet_count")
    )

    if volume_col:

        vals = pd.to_numeric(
            cleaned[volume_col],
            errors="coerce"
        ).dropna()

        if len(vals):

            fig, ax = plt.subplots(figsize=(10, 5.4))

            clipped = vals.clip(
                upper=vals.quantile(0.99)
            ).astype(float)

            ax.hist(
                clipped,
                bins=30,
                color="#9B6BFF",
                edgecolor="#E5CCFF",
                linewidth=0.7,
                alpha=0.92
            )

            style_chart(
                ax,
                f"Network Traffic Volume Distribution ({volume_col})",
                volume_col,
                "Frequency"
            )

            save_styled_figure(
                "04_traffic_volume_histogram.png"
            )

            summary_lines += [
                f"Traffic volume column: {volume_col}",
                vals.describe().to_string(),
                ""
            ]

    # LABEL ANALYSIS

    has_labels = "label" in mapping

    if has_labels:

        label_col = mapping["label"]

        labels = (
            cleaned[label_col]
            .fillna("Unknown")
            .astype(str)
            .str.strip()
        )

        label_counts = labels.value_counts()

        label_counts.to_csv(
            OUTPUT_DIR / "label_summary.csv",
            header=["records"]
        )

        normal_mask = labels.str.lower().str.contains(
            r"benign|normal",
            regex=True
        )

        normal_count = int(normal_mask.sum())

        attack_count = int(
            (
                ~normal_mask
                & labels.str.lower().ne("unknown")
            ).sum()
        )

        # DONUT CHART

        fig, ax = plt.subplots(figsize=(7, 6.5))

        fig.patch.set_facecolor(BG_COLOR)
        ax.set_facecolor(CARD_COLOR)

        pie_values = [
            normal_count,
            attack_count
        ]

        wedges, texts, autotexts = ax.pie(
            pie_values,
            labels=[
                "Normal / Benign",
                "Other labelled"
            ],
            autopct="%1.1f%%",
            startangle=90,
            colors=[
                "#65F0C1",
                "#B66CFF"
            ],
            wedgeprops={
                "width": 0.48,
                "edgecolor": BG_COLOR,
                "linewidth": 3
            },
            textprops={
                "color": TEXT_COLOR,
                "fontsize": 10
            }
        )

        for item in autotexts:
            item.set_color("#100B1D")
            item.set_fontweight("bold")

        ax.set_title(
            "Normal vs Other Labelled Records",
            color=TEXT_COLOR,
            fontsize=14,
            fontweight="bold",
            pad=18
        )

        save_styled_figure(
            "05_normal_vs_labelled_pie.png"
        )

        # ATTACK CATEGORY

        save_bar(
            label_counts.head(15),
            "Attack / Traffic Label Distribution",
            "Label",
            "Number of records",
            "06_attack_category_distribution.png",
            horizontal=True
        )

        summary_lines += [
            "Existing dataset labels (not invented):",
            label_counts.head(30).to_string(),
            f"Normal/Benign records: {normal_count:,}",
            f"Other labelled records: {attack_count:,}",
            ""
        ]

        if "protocol" in mapping:

            temp = pd.DataFrame({
                "protocol": protocols,
                "label": labels
            })

            cross = pd.crosstab(
                temp["protocol"],
                temp["label"]
            )

            cross.to_csv(
                OUTPUT_DIR / "protocol_by_label.csv"
            )

            summary_lines += [
                "Protocol by label:",
                cross.to_string(),
                ""
            ]

        if "destination_port" in mapping:

            temp = pd.DataFrame({
                "port": cleaned[mapping["destination_port"]],
                "label": labels
            })

            cross = pd.crosstab(
                temp["port"],
                temp["label"]
            )

            cross.to_csv(
                OUTPUT_DIR / "destination_port_by_label.csv"
            )

            summary_lines += [
                "Destination port by label (top ports):",
                cross.sum(axis=1)
                .sort_values(ascending=False)
                .head(10)
                .to_string(),
                ""
            ]

        if "source_ip" in mapping:

            attacks = cleaned.loc[
                ~normal_mask
                & labels.str.lower().ne("unknown")
            ]

            top = (
                attacks[mapping["source_ip"]]
                .astype(str)
                .value_counts()
                .head(10)
            )

            top.to_csv(
                OUTPUT_DIR / "top_source_ips_in_labelled_records.csv",
                header=["records"]
            )

            summary_lines += [
                "Source IPs with most non-normal labelled records:",
                top.to_string(),
                ""
            ]

    # RULE BASED REVIEW

    else:

        flags, reasons, rules = create_rule_flags(
            cleaned,
            mapping
        )

        cleaned["Needs_Review_Rule_Flag"] = flags
        cleaned["Review_Reason"] = reasons

        cleaned.to_csv(
            OUTPUT_DIR / "rule_based_review_records.csv",
            index=False
        )

        summary_lines += [
            "No recognized attack-label column was found.",
            "Rule-based screening was used; flagged rows are NOT confirmed attacks.",
            "Rules and thresholds:",
            *(rules or [
                "No usable numeric fields for rule-based screening."
            ]),
            f"Records flagged for review: {int(flags.sum()):,}",
            ""
        ]

        if "source_ip" in mapping and flags.any():

            top = (
                cleaned.loc[
                    flags,
                    mapping["source_ip"]
                ]
                .astype(str)
                .value_counts()
                .head(10)
            )

            summary_lines += [
                "Source IPs appearing most in rule-flagged records:",
                top.to_string(),
                ""
            ]

    # TRAFFIC TIMELINE

    if "timestamp" in mapping:

        time_col = mapping["timestamp"]

        times = pd.to_datetime(
            cleaned[time_col],
            errors="coerce"
        ).dropna()

        if len(times):

            timeline = (
                times.dt.floor("h")
                .value_counts()
                .sort_index()
            )

            timeline.to_csv(
                OUTPUT_DIR / "traffic_over_time.csv",
                header=["records"]
            )

            fig, ax = plt.subplots(figsize=(11, 5.4))

            ax.plot(
                timeline.index,
                timeline.values,
                color="#B66CFF",
                linewidth=2.5,
                marker="o",
                markersize=5,
                markerfacecolor="#35D6FF",
                markeredgecolor="#F4EEFF"
            )

            ax.fill_between(
                timeline.index,
                timeline.values,
                color="#9B6BFF",
                alpha=0.18
            )

            style_chart(
                ax,
                "Traffic Activity Over Time",
                "Timestamp (hour)",
                "Number of records"
            )

            fig.autofmt_xdate()

            save_styled_figure(
                "07_traffic_over_time.png"
            )

    # CORRELATION HEATMAP

    numeric = cleaned.select_dtypes(
        include=np.number
    )

    if numeric.shape[1] >= 2:

        corr = numeric.corr()

        corr.to_csv(
            OUTPUT_DIR / "numeric_correlation.csv"
        )

        fig, ax = plt.subplots(figsize=(12, 9))

        fig.patch.set_facecolor(BG_COLOR)

        sns.heatmap(
            corr,
            cmap="mako",
            center=0,
            linewidths=0.45,
            linecolor=BG_COLOR,
            annot=False,
            cbar_kws={"shrink": 0.8},
            ax=ax
        )

        ax.set_facecolor(CARD_COLOR)

        ax.set_title(
            "Correlation Between Numerical Network Traffic Fields",
            color=TEXT_COLOR,
            fontsize=14,
            fontweight="bold",
            pad=18
        )

        ax.tick_params(
            colors=MUTED_COLOR,
            labelsize=8
        )

        save_styled_figure(
            "08_numeric_correlation_heatmap.png"
        )

    # PORT AND PROTOCOL SUMMARY

    if (
        "protocol" in mapping
        and "destination_port" in mapping
    ):

        pd.crosstab(
            protocols,
            cleaned[mapping["destination_port"]]
        ).to_csv(
            OUTPUT_DIR / "protocol_by_destination_port.csv"
        )

    # FINAL REPORT

    summary_lines += [
        "INTERPRETATION CAUTION",
        "High traffic volume, unusual ports, or rule flags are indicators for further investigation,",
        "not proof that an IP address or activity is malicious.",
        "Dataset labels, when present, are reported as supplied by the dataset."
    ]

    report_path = REPORT_DIR / "analysis_summary.txt"

    report_path.write_text(
        "\n".join(summary_lines),
        encoding="utf-8"
    )

    return cleaned, summary_lines
