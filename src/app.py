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

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "Outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

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

SOFTWARE_SOLUTIONS = load_software_solutions(BASE_DIR / "Docs/insider_threat_solutions_weights.csv")

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
    _, center_col, _ = st.columns([0.25, 0.5, 0.25])

    if HEATMAP.exists():
        with center_col:
            st.markdown("<center><h2>Current Risk Analysis Heatmap</h2</center>", unsafe_allow_html=True)
            st.image(str(HEATMAP), caption="Risk Analysis Heatmap", width="stretch")
    else:
        st.info(
            "No loss distribution image found yet "
            f"(`{LOSS_DIST_IMG}`). Run the Monte Carlo simulation to generate it."
        )

    st.markdown("---")

    # Section 2: Select Mitigation Controls
    st.markdown("<center><h2>Configure Mitigation Controls</h2></center>", unsafe_allow_html=True)

    selections = {}
    left_col, _, right_col = st.columns([0.45, 0.05, 0.5])

    sorted_software_solutions = sorted(
        SOFTWARE_SOLUTIONS.items(),
        key=lambda item: item[1]["weight"],
        reverse=True
    )

    for label, meta in sorted_software_solutions:
        with right_col:
            selections[meta["key"]] = st.checkbox(
                f"{label} (${meta['cost']:,}/year)",
                value=False,
                key=meta["key"],
            )

    mitigation_weight, total_cost = calculate_weights_and_costs(selections)

    with right_col:
        st.write(f"**Total Annual Cost of Selected Controls:** \${total_cost:,}")
        simulate_col, deselect_col = st.columns([0.15, 0.85])
        with simulate_col:
            run_clicked = st.button("Simulate", type="primary")
        with deselect_col:
            deselect = st.button("Deselect all", type="secondary", on_click=lambda: [
                st.session_state.update({meta["key"]: False})
                for _, meta in SOFTWARE_SOLUTIONS.items()
            ])
        if run_clicked:
            with st.spinner("Running Monte Carlo simulation..."):
                generate_monte_carlo_results(mitigation_weight)
            st.success("Simulation complete. Figures and values updated below.")

        with st.container(border=True):
            st.markdown("### Loss Summary")
            stats = load_total_company_loss()
            if stats is None:
                st.info("No Monte Carlo statistics found yet. Try running the Monte Carlo simulation again.")
            else:
                mean_eal = stats.get("mean_eal")
                p5 = stats.get("p5")
                median = stats.get("median")
                p95 = stats.get("p95")
                min_loss = stats.get("min")
                max_loss = stats.get("max")

                if mean_eal is not None:
                    st.write(f"##### Mean EAL (Total Company Loss): \${mean_eal:,.0f}")
                if p5 is not None and p95 is not None:
                    st.write(f"- EAL for a good year: \${p5:,.0f}")
                    st.write(f"- EAL for a bad year: \${p95:,.0f}")
                if median is not None:
                    st.write(f"- Median: \${median:,.0f}")
                if min_loss is not None and max_loss is not None:
                    st.write(f"- Min / Max: \${min_loss:,.0f} / \${max_loss:,.0f}")

    with left_col:
        st.image(str(COMPARISON_IMG), caption="Baseline vs Mitigated Comparison", width="stretch")
        st.image(str(LOSS_DIST_IMG), caption="Insier Threat Loss Distribution", width="stretch")

if __name__ == "__main__":
    main()
