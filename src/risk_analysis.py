import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent   # moves from src/ → project root
OUTPUT_DIR = BASE_DIR / "Outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

OUTPUT_DIR_RISK = OUTPUT_DIR / "risk_analysis"
OUTPUT_DIR_RISK.mkdir(exist_ok=True)  


# Configuration
ROLES = ["C_Level", "Trader", "IT_Admin", "Analyst", "Contractor", "Exec_Assistant"]
REGIONS_ORDER = ["NA", "EU", "APAC"]
ROLE_HEADCOUNT = {
    "C_Level": 9,
    "Analyst": 700,
    "Trader": 100,
    "IT_Admin": 50,
    "Exec_Assistant": 20,
    "Contractor": 130
}
N_ITER = 10000
RANDOM_STATE = 42

# Load data
df = pd.read_csv(OUTPUT_DIR / "Dataset/billybank_activity.csv", keep_default_na=False)
df['region'] = df['region'].replace({np.nan: "NA"})

# Calculate annual probability = (# users with ≥1 malicious day) / (total users)
user_had_incident = df.groupby(['user_id', 'role', 'region'])['is_malicious'].agg([
    ('had_incident', lambda x: int(x.sum() > 0))
]).reset_index()

# Calculate probability by role
role_annual = (
    user_had_incident.groupby('role')['had_incident']
    .mean()  # Proportion of users who had ≥1 incident
    .reindex(ROLES)
)

# Role × Region breakdown
role_region_annual = (
    user_had_incident.groupby(['role', 'region'])['had_incident']
    .mean()
    .unstack()
    .reindex(index=ROLES, columns=REGIONS_ORDER, fill_value=0.0)
)

# Heatmap for risk analysis
# Build the heatmap using references from
# https://www.geeksforgeeks.org/python/display-the-pandas-dataframe-in-heatmap-style/ 

plt.figure(figsize=(10, 6))
sns.heatmap(
    role_region_annual * 100,
    annot=True, 
    fmt=".2f",
    cmap="YlOrRd",
    vmin=0,
    vmax=6,  # Cap at 6% for better visualization
    cbar_kws={'label': 'Annual Probability (%)'}
)
plt.title("Annual Insider Threat Probability by Role × Region", fontsize=14, fontweight='bold')
plt.ylabel("Role", fontsize=12)
plt.xlabel("Region", fontsize=12)
plt.tight_layout()
plot_path = OUTPUT_DIR_RISK / 'risk_heatmap.jpg'
plt.savefig(plot_path, dpi=300, bbox_inches='tight', format="jpeg")
# plt.show()

risk_scores_per_region = role_region_annual * 100  # Convert to percentage

# Convert to make a CSV
risk_csv = []
for role in risk_scores_per_region.index:
    for region in risk_scores_per_region.columns:
        risk_csv.append({
            'role': role,
            'region': region,
            'annual_probability_percent': risk_scores_per_region.loc[role, region],
            'headcount': ROLE_HEADCOUNT.get(role, 0)
        })

risk_df = pd.DataFrame(risk_csv)
csv_path = OUTPUT_DIR_RISK / 'risk_scores_by_region.csv'
risk_df.to_csv(csv_path, index=False)
