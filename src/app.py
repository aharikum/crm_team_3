import json
from pathlib import Path
import streamlit as st
from monte_carlo import generate_monte_carlo_results
import csv
import re
import plotly.graph_objects as go

st.set_page_config(
    page_title="BillyBank Insider Risk Dashboard",
    layout="wide",
)

# https://github.com/Sven-Bo/streamit-css-styling-demo/blob/main/assets/styles.css 
st.markdown("""
<style>
        .info{
            background: #eff6ff;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #3b82f6;
            margin: 1rem 0;
            color: #000000;
        }
        .info-metric{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #3b82f6;
        }
        .section {
            color: #1e3a8a;
            border-bottom: 2px solid #3b82f6;
            padding-bottom: 0.5rem;
            margin-top: 2rem;
            margin-bottom: 1rem;
        }        

</style>           
""", unsafe_allow_html=True)

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
    # _, center_col, _ = st.columns([0.25, 0.5, 0.25])
    st.markdown('<h2 class="section"> Current Risk Analysis</h2>', unsafe_allow_html=True)
    col1, col2 = st.columns([2,1])
    with col1:
        if HEATMAP.exists():
            st.image(str(HEATMAP), caption="Risk Analysis Heatmap - Probability by Role & Region", use_container_width=True)
        else:
            st.info(
                "No loss distribution image found yet "
                f"(`{LOSS_DIST_IMG}`). Run the Monte Carlo simulation to generate it."
            )
    with col2:
        # st.markdown("#### ")
        st.markdown("""
        <div class="info">
        <h4>Insigts from Dataset</h4>
        <strong>Highest Risk Roles:</strong>
        <ul>
            <li>Contractors (~2.09%)</li>
            <li>Exec Assistants (~1.44%)</li>
            <li>IT Admins (~1.36%)</li>
        </ul>
        
        <strong>Risk Factors:</strong>
        <ul>
            <li>Psychometric indicators</li>
            <li>Behavioural patterns</li>
            <li>HR flags</li>
            <li>Role-specific opportunities</li>
        </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Section 2: Select Mitigation Controls
    st.markdown('<h2 class="section">Configure Mitigation Controls</h2>', unsafe_allow_html=True)
    st.markdown("""
                <div class="info">
                Select security controls below to simulate their combined impact on insider threat risk. 
                Each control has a weighted effectiveness and annual cost. The simulation will calculate the reduced Expected Annual Loss (EAL)
                </div>
                """, unsafe_allow_html=True)
    selections = {}
    if "select_all" not in st.session_state:
        st.session_state["select_all"] = False
    if "deselect_all" not in st.session_state:
        st.session_state["deselect_all"] = False
    
    if st.session_state.get("select_all", False):
        for _, meta in SOFTWARE_SOLUTIONS.items():
            st.session_state[meta["key"]] = True
        st.session_state["select_all"] = False
    
    if st.session_state.get("deselect_all", False):
        for _, meta in SOFTWARE_SOLUTIONS.items():
            st.session_state[meta["key"]] = False
        st.session_state["deselect_all"] = False
    left_col, _, right_col = st.columns([0.45, 0.05, 0.5])

    col1, col2, col3 = st.columns(3)
    cols = [col1, col2, col3]
    sorted_software_solutions = sorted(
        SOFTWARE_SOLUTIONS.items(),
        key=lambda item: item[1]["weight"],
        reverse=True
    )

    for i, (label, meta) in enumerate(sorted_software_solutions):
        with cols[i % 3]:
            selections[meta["key"]] = st.checkbox(
                f"{label}",
                value=False,
                key=meta["key"],
                help=f"Effectiveness: {meta['weight']*100:.1f}% | Cost: {meta['cost']:,}/year"
            )

    mitigation_weight, total_cost = calculate_weights_and_costs(selections)

    st.markdown("---")
    metric1, metric2 = st.columns(2)
    with metric1:
        st.metric("Total Annual Cost", f"${total_cost:,}")
    with metric2:
        st.metric("Mitigation Coverage", f"${mitigation_weight*100:.1f}%")

    st.markdown("---")


    button1, button2, button3  = st.columns([1,1,4])

    with button1:
        if st.button("Select all", key="select_all_btn", use_container_width=True):
            st.session_state["select_all"] = True
            st.rerun()

    with button2:
        if st.button("Deselect all", key="deselect_all_btn", use_container_width=True):
            st.session_state["deselect_all"] = True
            st.rerun()
    
    st.markdown("---")
    _, col2, _ = st.columns([1,2,1])
    with col2:
        run_clicked = st.button("Run Simulation", type="primary")

    if run_clicked:
        with st.spinner("Running Monte Carlo simulation..."):
            generate_monte_carlo_results(mitigation_weight)
        st.success("Simulation complete. Figures and values updated below.")

    st.markdown("---")
    st.markdown('<h2 class=section>Simulation & Financial Impact</h2>', unsafe_allow_html=True)
    left_col, right_col = st.columns([3,2])
    with left_col:
        st.image(str(COMPARISON_IMG), caption="Baseline vs Mitigated Comparison", use_container_width=True)
        st.markdown("---")
        st.image(str(LOSS_DIST_IMG), caption="Insider Threat Loss Distribution", use_container_width=True)

    with right_col:
        st.markdown("### Financial Impact summary")
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
                st.markdown(f"""
                <div class="info-metric"> 
                    <h2 style="color: #1e3a8a; margin-top: 0;"> Mean Expected Annual Loss</h2>
                    <h3  style="color: #3b82f6; margin-top: 0;">${mean_eal:,.0f}</h3>
                    <h5  style="color: #000000; margin-top: 0;">EAL for a good year: ${p5:,.0f}</h5> 
                    <h5  style="color: #000000; margin-top: 0;">EAL for a bad year: ${p95:,.0f}</h5>
                </div>          
                """, unsafe_allow_html=True)
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("#### Distribution Statistics")
            if median is not None:
                st.metric("Median Loss", f"${median:,.0f}")
            if min_loss is not None and max_loss is not None:
                min_l, max_l = st.columns(2)
                with min_l:
                    st.metric("Min Loss", f"${min_loss:,.0f}")
                with max_l:
                    st.metric("Max Loss", f"${max_loss:,.0f}")

if __name__ == "__main__":
    main()
