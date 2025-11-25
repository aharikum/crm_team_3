# BillyBank Insider Threat Risk Model

## Summary

This project implements a comprehensive **insider threat risk quantification framework** for BillyBank, a fictional multinational investment bank. Using the **FAIR** framework, we quantify insider threat risk and produce **Expected Annual Loss (EAL)** estimates for executive decision making.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Pipeline Architecture](#pipeline-architecture)
3. [Stage 1: Data Generation](#stage-1-data-generation)
4. [Stage 2: Risk Analysis](#stage-2-risk-analysis)
5. [Stage 3: Monte Carlo Simulation](#stage-3-monte-carlo-simulation)
6. [Key Assumptions](#key-assumptions)
7. [Installation & Usage](#installation--usage)
8. [Validation & Calibration](#validation--calibration)
9. [Refereces & Citations](#references--citations)

---

## Project Overview

We need to fill this with overwiew of the organisation and what we needed to achieve
More information can be found in this - [Milestone 1](/Docs/CRM_Project_Milestone_1_%20Executive_Summary.pdf)

---

## Pipeline Architecture

The pipeline consists of three integrated stages:
1. **Data Generation** (`generator.py`) - Synthetic employee behavioral data
2. **Risk Analysis** (`risk_analysis.py`) - Probability calculations and heatmap visualization
3. **Monte Carlo Simulation** (`monte_carlo.py`) - Financial loss estimation with mitigation scenarios


![Architecture Diagram](/Docs/architecture.png)

*Figure: Architecture diagram*

---

## Stage 1: Data Generation

### File: `generator.py`

Generates **synthetic employee behavioral data** simulating 240 working days (approximately one year) for 1,009 users. The number of employee per role breakdown is given below

| Role | Count | Description |
|------|-------|-------------|
| C_Level | 9 | Executive leadership (CEO, CFO, CIO, CISO, etc.) |
| Analyst | 700 | Front-line business analysts |
| Trader | 100 | Trading floor personnel |
| IT_Admin | 50 | System administrators with privileged access |
| Exec_Assistant | 20 | Executive assistants with sensitive data access |
| Contractor | 130 | Temporary/external staff |

For each role, an employee is randomly placed in a region from the set of "NA", "EU" or "APAC".

**Note** The role headcounts in this simulation are intentionally reduced. Tracking 240 days of behavior per employee produces a very large dataset, and using real-world workforce sizes (~50,000 employees) would make the data unnecessarily heavy and computationally expensive.

### Behavioral Features 

Each daily observation includes 9 behavioral indicators:

| Feature | Description | Rationale |
|---------|-------------|-----------|
| `after_hours_logons` | Logins outside 8am-6pm | Anomalous access timing |
| `sensitive_file_reads` | Access to classified/PII files | Data exfiltration indicator |
| `usb_device_mounts` | Removable media usage | Physical data theft risk |
| `external_emails_sent` | Emails to non-corporate domains | Data leakage channel |
| `emails_with_attachments` | Emails containing files | Combined with external = high risk |
| `cloud_upload_events` | Uploads to cloud storage | Shadow IT / exfiltration |
| `failed_logins` | Authentication failures | Credential compromise indicator |
| `files_deleted` | File deletion activity | Sabotage / cover-up indicator |
| `http_competitor_visits` | Visits to competitor websites | Potential job-seeking / IP theft |

### Behavior Generation Model

#### Base Behavior (Normal Day)

Each role has defined **mean** and **standard deviation** values for each behavior:

```python
# Example: IT_Admin baseline behavior
ROLE_BEHAVIOR_BASE["IT_Admin"] = {
    "after_hours_logons": 2.0,      # IT often works off-hours
    "sensitive_file_reads": 15,      # Regular system access
    "usb_device_mounts": 0.2,        # Occasional device usage
    "files_deleted": 5,              # System maintenance
}
```

Daily behavior is sampled from a **Normal distribution** around these baselines:

```
Behavior_daily ~ Normal(μ_role, σ_role)
```

#### Psychometric Factors

Each user is assigned personality traits that influence risk:

| Trait | Description | Effect on Risk |
|-------|-------------|----------------|
| **Conscientiousness** | Rule-following tendency | Low means Higher risk |
| **Neuroticism** | Stress reactivity | High means Higher risk |

```python
# Example: Contractors have high variability
conscientiousness = Normal(50, 10)  # Average, high variance
neuroticism = Normal(52, 10)        # Slightly elevated stress
```

#### Malicious Behavior Probability

The daily probability of malicious behavior is calculated as:

```
P(malicious_day) = base_role_prob + (stress_factor × 0.000003) + (opportunity)
```

Where:
- **`base_role_prob`**: Role-specific baseline (0.005% to 0.02% per day)
- **`stress_factor`**: +1 for each: high neuroticism (>65), HR flag, low conscientiousness (<50)
- **`opportunity`**: 0.001% × opportunity_score (based on behavioral deviations beyond 2σ). The factors affecting oppertunity for a given role is defined in ROLE_OPPORTUNITY_WEIGHTS.

These probabilities are calibrated to produce **0.8% to 5% annual incident rates** per role

#### Daily Probability by Role

| Role | Base Daily Prob | Expected Annual Rate |
|------|-----------------|---------------------|
| C_Level | 0.005% | ~0% (very rare events) |
| Analyst | 0.008% | ~1.4% |
| Trader | 0.010% | ~2.0% |
| IT_Admin | 0.015% | ~3.5% |
| Exec_Assistant | 0.005% | ~0% |
| Contractor | 0.020% | ~4.7% |

The rational behind selecting Base daily probability is based on the roles and how much of a risk they are. For example Contractors normally would have higher daily probability than C_level. 

#### Behavioral Injection (Malicious Days)

When `is_malicious = 1`, role-specific behavioral spikes are injected:

```python
# Example: IT_Admin malicious day
row["after_hours_logons"]    += random.randint(3, 6)
row["sensitive_file_reads"]  += random.randint(40, 80)
row["usb_device_mounts"]     += random.randint(1, 3)
row["files_deleted"]         += random.randint(20, 50)
```

These patterns are based on the [CERT Insider Threat Research](https://ieeexplore.ieee.org/document/6565236) which identifies role specific exfiltration patterns. 

The Factor identification for BillyBank based off on the factors from the [SEI Dataset](https://www.sei.cmu.edu/library/insider-threat-test-dataset/) can be found in this - [Dataset Info](/Docs/Dataset%20info.pdf)

The output of this script can be found in - [BillyBank Activity](/Outputs/Dataset/billybank_activity.csv)

---

## Stage 2: Risk Analysis

### File: `risk_analysis.py`

Calculates **annual insider threat probability** by role and region from the BillyBank activity dataset.

### Probability Calculation

 We calculate the probability that an employee becomes a malicious insider at least once during the year, NOT the probability of any given day being malicious.

```
Annual Probability (per role) = (# users with ≥1 malicious day) / (total users in role)
```

**Process**:
1. For each user, determine if they had at least one malicious day across 240 days
2. Binary outcome: `had_incident = 1` if `is_malicious.sum() > 0`, else `0`
3. Calculate proportion of users in each role who had ≥1 incident

**Example**:
```python
# If 10 out of 700 Analysts had at least one malicious day:
Annual_Probability_Analyst = 10 / 700 = 0.0143 (1.43%)
```

### Role × Region Matrix

The analysis produces a probability matrix showing risk by role AND region:

| Role | NA | EU | APAC |
|------|------|------|------|
| C_Level | 0.00% | 0.00% | 0.00% |
| Trader | 2.94% | 3.23% | 0.00% |
| IT_Admin | 7.14% | 0.00% | 0.00% |
| Analyst | 1.83% | 1.36% | 1.15% |
| Contractor | 5.41% | 7.55% | 5.00% |
| Exec_Assistant | 0.00% | 0.00% | 0.00% |

This can be viewed as a heatmap [here](/Outputs/risk_analysis/risk_heatmap.jpg) and as a csv [here](/Outputs/risk_analysis/risk_scores_by_region.csv).
Since the dataset we generated remains the same, the above two files are also constant as it describes the risk in the given year.

---

## Stage 3: Monte Carlo Simulation

### File: `monte_carlo.py`

Performs **10,000 Monte Carlo iterations** to generate a probabilistic distribution of annual losses, producing EAL.

### FAIR Framework Components

The simulation implements the **FAIR** model:

| FAIR Component | Implementation | Value |
|----------------|----------------|-------|
| **Probability of Action (PoA)** | % of users per role with ≥1 incident | Calculated from Stage 2 |
| **Threat Event Frequency (TEF)** | Expected insiders per year = Headcount × PoA | Varies by role |
| **Contact Frequency (CF)** | Attempts per insider per year | Poisson(3.5) |
| **Vulnerability (V)** | Attack success rate | 75% baseline |
| **Loss Magnitude (LM)** | Financial impact per successful attack | Lognormal distribution |
| **Loss Event Frequency (LEF)** | TEF × CF × V = `n_insiders × attempts × success_rate` | Varies by role|
| **Expected Annual Loss (EAL)** | TEF × CF × V × LM | Output of this script |

### Simulation Algorithm

For each of 10,000 iterations:

```
For each role:
    1. Sample number of malicious insiders
       n_insiders ~ Binomial(headcount, PoA)
    
    2. Sample attack attempts per insider
       attempts_per_insider ~ Poisson(3.5)
       total_attempts = sum(attempts_per_insider)
    
    3. Sample successful attacks
       n_successful ~ Binomial(total_attempts, Vulnerability × (1 - mitigation))
    
    4. Sample loss per successful attack
       log_mean = (log(min_loss) + log(max_loss)) / 2
       log_std = (log(max_loss) - log(min_loss)) / 4
       losses ~ Lognormal(log_mean, log_std)
       losses = clip(losses, min_loss, max_loss)
    
    5. Aggregate
       role_loss = sum(losses)
       total_loss += role_loss
```

### Loss Magnitude Mapping

Losses are mapped to role based on real-world incident data. This can be viewed from the [employee Loss Ranges](/Docs/employee_loss_ranges.csv) file.

### Why do we use a Lognormal Distribution 

Financial losses are modeled with **lognormal distribution** because:
1. **Right-skewed**: Most incidents cause moderate damage, but catastrophic events create extreme outliers
2. **Strictly positive**: Losses cannot be negative
3. **Multiplicative effects**: Financial impacts often compound

**Parameter Calculations**:
```python
log_mean = (log(min_loss) + log(max_loss)) / 2  # Geometric mean
log_std = (log(max_loss) - log(min_loss)) / 4   # 95% within [min, max]
```

The standard deviation is calibrated so that 95% of samples fall within the min/max range (per the 68-95-99.7 rule, ±2σ covers ~95% of the distribution).

### Mitigation Modeling

The simulation supports **mitigation scenarios** that reduce vulnerability:

```python
Effective_Vulnerability = Base_Vulnerability × (1 - mitigation_weight)

# Example: 70% mitigation investment
Effective_Vulnerability = 0.75 × (1 - 0.70) = 0.225 (22.5%)
```

This models the impact of investments like:

| Rank | Layer                                      | Weight | Rationale                                                                                     |
|------|--------------------------------------------|--------------|------------------------------------------------------------------------------------------------|
| 1    | Privileged Access & Session Recording (PAM) | 15           | Prevents privileged misuse and provides accountable session evidence.                         |
| 2    | Insider Risk & DLP                         | 12           | Blocks data exfiltration and protects sensitive customer information.                         |
| 3    | SIEM + UEBA                                | 11           | Detects behavioral anomalies and disrupts malicious insider activity.                         |
| 4    | Phishing-Resistant Authentication (AAL3/FIDO2) | 7        | Eliminates credential sharing and reduces phishing-based impersonation.                       |
| 5    | Database Activity Monitoring (DAM)         | 6            | Monitors sensitive DB activity and enables rapid detection of misuse.                         |
| 6    | Immutable Audit Trail (WORM / Ledger)      | 6            | Prevents log tampering and strengthens non-repudiation.                                       |
| 7    | Digitally Signed Approvals                 | 5            | Provides traceable, verifiable authorization for sensitive actions.                           |
| 8    | Signed Transport Logging (RFC 5848)        | 4            | Adds cryptographic integrity to log transport pipelines.                                      |
| 9    | NIST AU-10 Governance / Controls Alignment | 4            | Establishes governance standards that reinforce non-repudiation.                              |

Complete information about the mitigation research can be found here - [Cost Scale](/Docs/non_repudiation_costs_chase_scale.csv) and [Threat Solution Weights](/Docs/insider_threat_solutions_weights.csv)
 

This is the last stage of our backend. The file outputs from this script are:
- [mitigation_comparison.jpeg](/Outputs/monte_carlo_results/mitigation_comparison.jpg) - This shows the EAL per role as a comparison with and without any mitigation
- [monte_carlo_loss_distribution.jpg](/Outputs/monte_carlo_results/monte_carlo_loss_distribution.jpg) - This is an overlapping histogram that shows the monte carlo loss per iteration for each role
- [monte_carlo_resuts.json](/Outputs/monte_carlo_results/monte_carlo_results.json) - A json output of the above two information as well as an aggregated company loss statistics for the front end to display.

---

## Key Assumptions

### Data Generation Assumptions

| Assumption | Value | Justification |
|------------|-------|---------------|
| Working days per year | 240 | Standard business year (excludes weekends/holidays) |
| Random seed | 1337 | Reproducibility |
| User behavior independence | Yes | Employee actions are independent |
| Psychometric stability | Fixed per user | Personality doesn't change within simulation period |
| HR flag probability | 0.01-0.2% per day | Based on typical HR incident rates |

### Risk Model Assumptions

| Assumption | Value | Justification |
|------------|-------|---------------|
| Binary incident classification | 0/1 | User either became malicious or not |
| Annual probability = at least one incident | Yes | Consistent with industry risk reporting |
| Regional variation | Captured | Different regional compliance/culture |

### Monte Carlo Assumptions

| Assumption | Value | Justification |
|------------|-------|---------------|
| Baseline vulnerability | 75% | Insiders have legitimate access - high success rate |
| Contact frequency | Poisson(3.5) | Insiders don't continuously attack|
| Loss distribution | Lognormal | Right skewed financial impacts |
| Independence of events | Yes | Binomial sampling assumes independent employees |
| Iterations | 10,000 | Statistical convergence |
| Mitigation effectiveness | Configurable (0-100%) | Allows scenario planning |

---

## Installation & Usage

### Prerequisites

- Python 3.8+
- pip package manager

### Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Pipeline

Execute in order:

```bash
# Step 1: Generate synthetic data
python3 generator.py
# Output: billybank_activity_updated.csv

# Step 2: Calculate risk probabilities
python3 risk_analysis.py
# Output: risk_analysis/

# Step 3: Run Monte Carlo simulation
python3 monte_carlo.py
# Output: monte_carlo_results/
```

### Configuring Mitigation Scenarios

Edit `monte_carlo.py` to adjust mitigation weight:

```python
# Default: 70% mitigation effectiveness
generate_monte_carlo_results(mitigation_weight=0.7)

# No mitigation (baseline)
generate_monte_carlo_results(mitigation_weight=0.0)

# 50% mitigation
generate_monte_carlo_results(mitigation_weight=0.5)
```
---

## Validation & Calibration

### Industry Benchmarks

The generated data is calibrated against industry research:

| Metric | Our Model | Industry Benchmark | Source |
|--------|-----------|-------------------|--------|
| Annual insider incident rate | 1-5% | 0.5-3% | CERT Insider Threat Center |
| Contractor elevated risk | ~5.8% | Higher than FTEs | Multiple studies |
| IT Admin elevated risk | ~2.4% | 2-4× average | Privileged access research |

### Validation Checks

1. **Distribution shape**: Malicious days are rare (< 0.1% of total observations)
2. **Role ordering**: Contractors and IT_Admin show highest risk (expected)
3. **Loss magnitude**: Monte Carlo outputs align with real-world incident ranges
4. **Mitigation ROI**: 70% mitigation yields ~70% risk reduction (linear assumption)

### Known Limitations

1. **Synthetic data**: Real behavioral patterns may differ
2. **Independence assumption**: Correlated insider threats (e.g., collusion) not modeled
3. **Static psychometrics**: Personality changes over time not captured
4. **Loss estimation uncertainty**: Real losses are highly context-dependent
5. **Small C-Level sample**: 9 executives limits statistical power for that role

---

## References & Citations

- cert
- sources
  
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html

  https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html

  https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview

  https://learn.microsoft.com/en-us/azure/confidential-ledger/overview

  https://cloud.google.com/storage/docs/bucket-lock

  https://datatracker.ietf.org/doc/html/rfc5848

  https://www.splunk.com/en_us/products/pricing/faqs/cyber-security.html

  https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-sentinel

  https://cloud.google.com/security/products/security-operations

  https://www.elastic.co/docs/solutions/security

  https://www.ibm.com/products/guardium-data-protection

  https://www.imperva.com/products/data-activity-monitoring/

  https://www.varonis.com/data-security-platform

  https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/privileged-session%20manager-introduction.htm

  https://docs.delinea.com/online-help/secret-server/session-recording/index.htm

  https://www.beyondtrust.com/docs/privileged-identity/app-launcher-and-recording/configure/session-recording-settings.htm

  https://support.oneidentity.com/technical-documents/safeguard-for-privileged-sessions/7.3.1/administration-guide

  https://learn.microsoft.com/en-us/purview/insider-risk-management

  https://www.broadcom.com/products/cybersecurity/information-protection/data-loss-prevention

  https://docs.netskope.com/en/data-loss-prevention/

  https://pages.nist.gov/800-63-4/sp800-63b.html

  https://support.docusign.com/s/document-item?topicId=gpa1578456339545.html

  https://nvd.nist.gov/800-53

  https://www.cisa.gov/insider-threat-mitigation; https://www.cyberark.com/resources

  https://www.microsoft.com/en-us/security/business/risk-management/insider-risk-management

  https://www.broadcom.com/products/cybersecurity/information-protection/data-loss-prevention

  https://www.splunk.com/en_us/data-insider/what-is-user-and-entity-behavior-analytics.html

  https://cloud.google.com/chronicle

  https://pages.nist.gov/800-63-4/sp800-63b.html

  https://fidoalliance.org

  https://www.ibm.com/products/guardium-data-protection

  https://www.imperva.com/learn/data-security/database-activity-monitoring-dam/

  https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html

  https://learn.microsoft.com/en-us/azure/confidential-ledger/overview

  https://support.docusign.com

  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf

  https://datatracker.ietf.org/doc/html/rfc5848

  https://nvd.nist.gov/800-53

  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

  https://en.wikipedia.org/wiki/2012_JPMorgan_Chase_trading_loss

  https://elischolar.library.yale.edu/cgi/viewcontent.cgi?article=1013&context=journal-of-financial-crises

  https://www.federalreserve.gov/newsevents/pressreleases/enforcement20240314a.htm

  https://www.cftc.gov/PressRoom/PressReleases/8914-24

  https://www.justice.gov/usao-edny/pr/former-jp-morgan-chase-bank-employee-sentenced-four-years-prison-selling-customer

  https://www.reuters.com/article/idUSBREA4D0G3/

  https://www.sec.gov/files/litigation/admin/2018/34-83858.pdf

  https://www.sfchronicle.com/bayarea/article/bay-area-bank-worker-charged-stealing-nearly-1-20363841.php

  https://apnews.com/article/53ef64672b07976ae5d3960e75246285

  https://www.justice.gov/usao-nj/pr/td-bank-insider-pleads-guilty-accepting-bribes-fraudulently-open-more-100-bank-accounts

  https://www.justice.gov/archives/opa/pr/td-bank-insider-arrested-and-charged-facilitating-money-laundering

  https://www.justice.gov/usao-wdmo/pr/former-bank-employee-pleads-guilty-24-million-embezzlement-scheme

  https://www.fayettenewspapers.com/stories/bond-company-sues-exchange-bank-over-money-embezzled-by-former-employee%2C165810

  https://www.justice.gov/usao-ct/pr/bank-general-counsel-sentenced-4-years-prison-74-million-embezzlement-scheme

  https://www.irs.gov/compliance/criminal-investigation/bank-general-counsel-pleads-guilty-to-offenses-stemming-from-7-point-4-million-embezzlement-scheme

  https://abcnews.go.com/US/bank-manager-sentenced-position-steal-200000-directly-customer/story?id=115595925

  https://www.wsj.com/finance/regulation/morgan-stanley-is-fined-over-first-republic-insider-sales-48ad84bf

  https://www.americanbanker.com/news/finwise-waited-a-year-to-disclose-a-breach-affecting-689-000

  https://www.bankingdive.com/news/finwise-data-breach-former-employee-american-first-court-plaintiff-689k/761026/

  https://www.theguardian.com/business/2008/jan/24/creditcrunch.banking

  https://en.wikipedia.org/wiki/2008_Soci%C3%A9t%C3%A9_G%C3%A9n%C3%A9rale_trading_loss

  https://en.wikipedia.org/wiki/2011_UBS_rogue_trader_scandal

  https://www.fca.org.uk/publication/final-notices/ubs-ag.pdf

  https://www.investopedia.com/ask/answers/08/nick-leeson-barings-bank.asp

  https://en.wikipedia.org/wiki/John_Rusnak

  https://www.justice.gov/archive/dag/cftf/chargingdocs/allfirst.pdf

  https://www.latimes.com/archives/la-xpm-1995-09-27-fi-50502-story.html

  https://www.theguardian.com/business/2020/jul/24/goldman-sachs-settle-1mdb-corruption-scandal-malaysia

  
Prompts from GPT

Insider Threat Table Prompts

<img width="562" height="148" alt="Screenshot 2025-11-24 at 9 52 31 PM" src="https://github.com/user-attachments/assets/983f9455-cab9-4baf-9fd8-d7cf22537163" />
This is what got us started with the cases, and then found sources based on them and began creating notes from sources that are lsited above.

<img width="643" height="497" alt="Screenshot 2025-11-24 at 9 51 35 PM" src="https://github.com/user-attachments/assets/dac79402-14f2-49b9-b262-dae298f4b1d0" />

<img width="575" height="142" alt="Screenshot 2025-11-24 at 9 52 17 PM" src="https://github.com/user-attachments/assets/4633cd5c-baf3-40eb-83a5-7ed6493ea44e" />

<img width="589" height="145" alt="Screenshot 2025-11-24 at 9 52 07 PM" src="https://github.com/user-attachments/assets/57447a19-1124-44f4-9651-1d1c3e3d0875" />






---
