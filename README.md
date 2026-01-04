# QoS-Aware Spatio-Temporal Graph Neural Network (ST-GNN) for IP Flow Anomaly Detection

## 📌 Project Overview
This project implements a **QoS-Aware Spatio-Temporal Graph Neural Network (ST-GNN)** to detect network anomalies in the **UNSW-NB15** dataset. It addresses the limitations of static detection methods by modeling network flows as dynamic graphs, allowing the system to capture:
1.  **Temporal Dynamics:** Evolution of attacks over time (e.g., DoS ramp-up).
2.  **Structural Relationships:** Inter-flow connections via shared IPs (topology).
3.  **QoS Fidelity:** Leveraging Jitter, Packet Loss, and TCP Windows for high-precision detection.

---

## 🔬 Methodology: QoS-Aware Spatio-Temporal GNN

Our approach is grounded in a rigorous scientific methodology designed to maximize detection accuracy and robustness in high-dimensional network environments.

### 1. Data Preprocessing & Feature Engineering
To address high dimensionality and statistical skew:
*   **Temporal Binning:** Network flows are segmented into **15-second time snapshots**, transforming the problem into a time-series graph analysis.
*   **QoS Metric Extraction:** Engineered features for jitter (`sjit`, `djit`), packet loss (`sloss`, `dloss`), and TCP window sizes (`swin`, `dwin`) provide high-fidelity signals for anomalies invisible to header inspection.
*   **Quantile Normalization:** Applied Quantile Transformation to map power-law feature distributions to Gaussian outputs, ensuring gradient stability during training.

### 2. Taxonomy Aggregation (The 5-Class Strategy)
We refined the original 10-class taxonomy into **5 semantic super-classes** to enhance generalization:
*   **Classes:** `Normal`, `Generic`, `DoS`, `Reconnaissance`, `Malware`.
*   **Optimization:** This shift moves the objective from brittle "Tool Identification" to robust **"Intent Recognition"**. It creates distinct, separable clusters in the latent space, boosting F1-scores for minority classes like *Reconnaissance* and *DoS* which often share fingerprints with *Analysis* or *Backdoors*.

### 3. Dynamic Graph Construction
We construct a sequence of dynamic graphs $G_t = (V_t, E_t)$ for each time bin $t$:
*   **Nodes ($V_t$):** Active IP flows.
*   **Structural Edges:** Connect flows sharing a Source or Destination IP (capturing fan-in/fan-out topologies).
*   **Behavioral Edges:** Connect flows with similar statistical behaviors (via KNN on QoS metrics), enabling detection of distributed attacks (e.g., Botnets).

### 4. Model Architecture: Deep Residual ST-GNN
The core detection engine is a custom **Deep Residual Spatio-Temporal GNN**:
*   **Spatial Encoder (GATv2):** Uses **Graph Attention Networks v2** with multi-head attention to dynamically assign importance to neighbors (e.g., attending to high-rate neighbors during a DoS attack).
*   **Deep Residual Connections:** Skips connections (`x + res(x)`) preserve granular flow details while aggregating neighborhood context.
*   **Jumping Knowledge (JK):** Aggregates outputs from all layers to retain both **local anomalies** (QoS spikes) and **global anomalies** (graph structure) for the final prediction.

### 5. Why This Yields Optimal Results
1.  **Contextual Awareness:** The ST-GNN sees **relationships**, not just rows. It detects malicious intent based on structural connections to anomalous clusters.
2.  **QoS Sensitivity:** Embedding QoS metrics allows detection of "Low-Rate DoS" and "Slow-Scan" attacks that evade simple volume filters.
3.  **Semantic Robustness:** The 5-class taxonomy minimizes decision ambiguity, maximizing the F1-score across all categories.


---

## 📂 Project Structure

```bash
├── data/                   # Dataset files (UNSW-NB15)
├── models/                 # Saved machine learning models (.pkl)
├── SDN/                    # SDN Controller and Network Topologies
│   ├── nids_controller.py  # Basic controller logic
│   ├── nids_controller_ml.py # ML-enhanced controller (ST-GNN)
│   ├── topology.py        # Static network topology
│   └── traffic_gen.py     # Attack traffic generator
├── train/                  # Training utility scripts
├── utils/                  # Helper functions for graph construction
├── train_stgnn.py          # Main model training script
├── generate_topology_from_data.py # Script to create topology from dataset
└── requirements.txt        # Python dependencies
```

---


## 🚀 Usage

### Requirements
See `requirements.txt` for the full list. Key dependencies:
*   `torch` & `torch-geometric`
*   `pandas`, `numpy`
*   `scikit-learn`
*   `ryu` (For SDN Simulation)
*   `mininet` (For SDN Simulation)
*   `scapy` (For Traffic Gen)

### Running the Training Pipeline
To train the ST-GNN model using the preprocessed UNSW-NB15 dataset:

```bash
python train_stgnn.py
```

This will:
1.  Load the dataset and construct dynamic graph snapshots.
2.  Initialize the **Deep Residual ST-GNN** architecture.
3.  Train usage **Graph Batch Balancing** to handle class imbalance.
4.  Evaluate using the **QoS-Aware Attention Mechanism**.
5.  Save the best model to `models/stgnn_model.pkl`.

---

## 🛡️ SDN Simulation Guide (Phase 2 & 3)

This section explains how to run the Real-Time NIDS Simulation using **Ryu** and **Mininet** on your Kali Linux (or Ubuntu) VM.

### 📦 1. Dependencies (Install on VM)

You need to install these python libraries **inside your Linux VM**.

```bash
# System Dependencies
sudo apt-get update
sudo apt-get install mininet openvswitch-switch python3-pip

# Python Dependencies
sudo pip3 install ryu scapy pandas scikit-learn joblib
```

> **Note:** Make sure you transfer the `SDN/` folder and the `models/` folder from your Windows machine to your Linux VM.

### 🚀 2. How to Execute

#### Step 1: Start the Controller (Terminal 1)
The controller is the "Brain". It must act first to listen for switches.

**For Basic Logic (Phase 2):**
```bash
ryu-manager SDN/nids_controller.py
```

**For ML Model Logic (Phase 3):**
```bash
ryu-manager SDN/nids_controller_ml.py
```
*You should see logs saying "Loading App..." and eventually "Loaded ST-GNN Model".*

#### Step 2: Start the Topology (Terminal 2)
The topology creates the virtual network (Switches + Hosts).

**Option A: Static Topology (Phase 2)**
```bash
sudo python3 SDN/topology.py
```

**Option B: Data-Driven Topology (Phase 3)**
*First generate the topology file from the dataset:*
```bash
python3 generate_topology_from_data.py
```
*Then run it:*
```bash
sudo python3 SDN/topology_data.py
```

### 🖥️ 3. Accessing Hosts & Generating Traffic

Once Mininet is running (in Terminal 2), you will see a prompt like `mininet>`.

To open individual terminals for each host:
```bash
mininet> xterm h1 h2
```

1.  **On h1 (Victim):** (Optional) Run a server:
    ```bash
    python3 -m http.server 80
    ```

2.  **On h2 (Attacker):** Run the traffic generator:
    ```bash
    python3 SDN/traffic_gen.py
    ```
    *   Select **Option 2 (DoS)** or **Option 3 (Recon)** from the menu.

### 🦈 4. Verification

1.  **Check Controller Log:** You should see `[ALERT] DoS Detected! Blocking...`.
2.  **Wireshark:** Capture on interface `s1-eth1`. You will see traffic start and then stop abruptly when the block rule is triggered.

## 🔧 Troubleshooting (Kali Linux / Common Errors)

If you encounter issues while setting up the SDN environment, try these fixes:

### 1. Ryu Manager Crash (`ALREADY_HANDLED` or `TimeoutError`)
This is caused by a conflict between Ryu and newer Python versions.
**Fix:**
```bash
# 1. Install compatible eventlet
sudo pip3 install eventlet==0.33.3 --break-system-packages --ignore-installed

# 2. Patch the Ryu library to define the missing variable
sudo sed -i '/class _AlreadyHandledResponse(Response):/i ALREADY_HANDLED = object()' /usr/local/lib/python3.11/dist-packages/ryu/app/wsgi.py
```

### 2. Open vSwitch Database Failed
Error: `ovs-vsctl: unix:/var/run/openvswitch/db.sock: database connection failed`
**Fix:** Start the service manually.
```bash
sudo service openvswitch-switch start
```

### 3. Model Not Found
Error: `[NIDS] ERROR: Model file models/stgnn_model.pkl not found.`
**Fix:** Ensure the `models/` directory is inside the `SDN/` directory where you are running the script.
```bash
cp -r ../models .  # Adjust path as needed
```
