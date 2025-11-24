import json
from pathlib import Path
import streamlit as st
from monte_carlo import generate_monte_carlo_results
import csv
import re

st.set_page_config(
    page_title="BillyBank Insider Risk Dashboard",
    layout="wide",
)

OUTPUT_DIR = Path("../Outputs")
HEATMAP = OUTPUT_DIR / "risk_analysis" / "risk_heatmap.jpg"
LOSS_DIST_IMG = OUTPUT_DIR / "monte_carlo_results" / "monte_carlo_loss_distribution.jpg"
COMPARISON_IMG = OUTPUT_DIR / "monte_carlo_results" / "mitigation_comparison.jpg"
RESULTS_JSON = OUTPUT_DIR / "monte_carlo_results" / "monte_carlo_results.json"

def load_software_solutions(csv_path):
    software_solutions = {}
    with open(csv_path, newline="") as file:
        reader = csv.reader(file)
        next(reader) # Skip header row
        for row in reader:
            name = row[1].strip()
            weight = float(row[2]) / 100.0
            cost = int(row[3])
            key = re.sub(r"[^a-z0-9]", "", name.lower())
            software_solutions[name] = {
                "key": key,
                "cost": cost,
                "weight": weight
            }

    return software_solutions

SOFTWARE_SOLUTIONS = load_software_solutions("../Docs/insider_threat_solutions_weights.csv")

def calculate_weights_and_costs(selections):
    mitigation_weight = 0.0
    total_cost = 0

    for _, meta in SOFTWARE_SOLUTIONS.items():
        if selections.get(meta["key"], False):
            mitigation_weight += meta["weight"]
            total_cost += meta["cost"]

    return mitigation_weight, total_cost

def load_total_company_loss():
    if not RESULTS_JSON.exists():
        return None

    try:
        with open(RESULTS_JSON, "r") as f:
            data = json.load(f)
        return data.get("total_company_loss")
    except Exception:
        return None

def main():
    st.markdown("<center><h1>BillyBank Insider Risk Dashboard</h1></center>", unsafe_allow_html=True)

    st.markdown("---")

    # Section 1: Heatmap / Loss Distribution
    st.markdown("## 1. Current Risk Analysis Heatmap")
    left_col, center_col, right_col = st.columns([0.25, 0.5, 0.25])

    if HEATMAP.exists():
        with center_col:
            st.image(str(HEATMAP), caption="Risk Analysis Heatmap", width="stretch")
    else:
        st.info(
            "No loss distribution image found yet "
            f"(`{LOSS_DIST_IMG}`). Run the Monte Carlo simulation to generate it."
        )

    st.markdown("---")

    # Section 2: Select Mitigation Controls
    st.markdown("## 2. Configure Mitigation Controls")

    selections = {}
    # col1, col2 = st.columns([0.2, 0.8])
    # col1, col2 = st.columns([0.9, 0.1])

    sorted_software_solutions = sorted(
        SOFTWARE_SOLUTIONS.items(),
        key=lambda item: item[1]["weight"],
        reverse=True
    )

    for i, (label, meta) in enumerate(sorted_software_solutions):
        # with (col1 if i % 2 == 0 else col2):
        # with col1:
            # selections[meta["key"]] = st.checkbox(
            #     f"{label} (${meta['cost']:,}/year)",
            #     value=False,
            #     key=meta["key"],
            # )
        selections[meta["key"]] = st.checkbox(
            f"{label} (${meta['cost']:,}/year)",
            value=False,
            key=meta["key"],
        )

    mitigation_weight, total_cost = calculate_weights_and_costs(selections)

    st.write(f"**Total Annual Cost of Selected Controls:** ${total_cost:,}")

    run_clicked = st.button("Simulate", type="primary")
    if run_clicked:
        with st.spinner("Running backend Monte Carlo simulation..."):
            generate_monte_carlo_results(mitigation_weight)
        st.success("Simulation complete. Dashboard updated below.")

    st.markdown("---")

    # Section 3: Monte Carlo Outputs (images + JSON stats)
    left_col, right_col = st.columns(2)

    with left_col:
        st.markdown("### 3.1 Loss Distribution & Mitigation Comparison")

        if COMPARISON_IMG.exists():
            st.image(str(COMPARISON_IMG), caption="Baseline vs Mitigated Comparison", width="stretch")
        else:
            st.warning(
                f"`{COMPARISON_IMG.name}` not found in `{OUTPUT_DIR}`. "
                "Run the simulation to generate it."
            )

        st.markdown("---")

        if LOSS_DIST_IMG.exists():
            st.image(str(LOSS_DIST_IMG), caption="Insider Threat Loss Distribution", width="stretch")
        else:
            st.warning(
                f"`{LOSS_DIST_IMG.name}` not found in `{OUTPUT_DIR}`. "
                "Run the simulation to generate it."
            )

    with right_col:
        st.markdown("### 3.2 Total Company Loss Summary")

        stats = load_total_company_loss()
        if stats is None:
            st.info(
                "No Monte Carlo statistics found yet. "
                f"Expected a `total_company_loss` section in `{RESULTS_JSON.name}`. "
                "Run the simulation to generate it."
            )
        else:
            mean_eal = stats.get("mean_eal")
            p5 = stats.get("p5")
            median = stats.get("median")
            p95 = stats.get("p95")
            min_loss = stats.get("min")
            max_loss = stats.get("max")

            if mean_eal is not None:
                st.metric("Mean EAL (Total Company Loss)", f"${mean_eal:,.0f}")
            st.write("**Distribution (Total Company Loss):**")
            if p5 is not None and p95 is not None:
                st.write(f"- 5th-95th percentile: \${p5:,.0f} - \${p95:,.0f}")
            if median is not None:
                st.write(f"- Median: \${median:,.0f}")
            if min_loss is not None and max_loss is not None:
                st.write(f"- Min / Max: \${min_loss:,.0f} / \${max_loss:,.0f}")

if __name__ == "__main__":
    main()
