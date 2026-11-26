# Cybersecurity Threat Detection and Analysis Using Python

A defensive, Python-only data analytics project. It explores network-flow/security-log CSV data, summarizes traffic, analyzes existing attack labels when present, and otherwise reports rule-based records that need review. It does **not** use Machine Learning, Deep Learning, SQL, Excel, Power BI, or Tableau.

## 1. Dataset
Recommended public dataset: **CICIDS2017**, provided by the Canadian Institute for Cybersecurity:
https://www.unb.ca/cic/datasets/ids-2017.html

Download a CSV file from the dataset's CSV section and place it in `Dataset/`. Rename it to `cybersecurity_data.csv`.
The original CICIDS2017 download can be large. Start with one CSV file/day if your computer has limited memory. The code accepts common CICIDS2017 field names and common alternatives.

**Important:** `Dataset/demo_cybersecurity_data.csv` is a tiny, clearly-labelled DEMO file created only to test that the project runs. It is not the public dataset and must not be presented as real research data. Replace it with the downloaded public CSV before preparing final findings.

## 2. Setup (Windows PowerShell)
```powershell
cd path\to\CYBERSECURITY_THREAT_ANALYSIS
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
```

## 3. Run
1. Put the downloaded dataset at `Dataset/cybersecurity_data.csv`.
2. Run `python main.py`. If the public CSV is not present yet, the program uses the clearly marked demo CSV only to test the workflow.
3. Open `Notebooks/` in Jupyter and run notebooks 01 to 06 in order.
4. View charts in `Graphs/`, tables in `outputs/`, and the generated summary in `Final_Report/`.

To test without downloading the public dataset, copy `Dataset/demo_cybersecurity_data.csv` to `Dataset/cybersecurity_data.csv` and run the project. Clearly identify this as demo data in any demonstration.

## 4. Project structure
```text
CYBERSECURITY_THREAT_ANALYSIS/
├── Dataset/
│   ├── cybersecurity_data.csv       # place downloaded public CSV here
│   └── demo_cybersecurity_data.csv  # test data only
├── Notebooks/
│   ├── 01_data_loading.ipynb
│   ├── 02_data_understanding.ipynb
│   ├── 03_data_cleaning.ipynb
│   ├── 04_traffic_analysis.ipynb
│   ├── 05_threat_analysis.ipynb
│   └── 06_data_visualization.ipynb
├── Graphs/
├── outputs/
├── Final_Report/
├── src/
│   └── analysis_utils.py
├── main.py
├── requirements.txt
└── README.md
```

## 5. Analysis notes
- Existing dataset labels are analyzed as supplied; labels are not invented.
- If no label column exists, simple transparent rules flag unusual records for review. These are **indicators, not proof of malicious activity**.
- Some datasets do not include source IP, destination IP, timestamp, packet count, or byte count. The program reports unavailable fields and skips only the related analysis/chart.
- Protocol numeric values are mapped for common values: 1=ICMP, 6=TCP, 17=UDP. Other values remain visible as their original values.
- Large datasets may take time and memory. If needed, use a smaller CSV or a representative subset and disclose that in the report.

## 6. Suggested report sections
1. Introduction and objective
2. Dataset source, file name, size, and available columns
3. Data loading and understanding
4. Data cleaning performed
5. Traffic analysis
6. Threat analysis (existing labels OR rule-based review indicators)
7. Visualizations and interpretation
8. Limitations and conclusion

## Dataset citation
Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.


## 7. Purple Login and Dashboard UI
The Flask web interface includes:
- Admin login (credentials configured in environment variables).
- User registration and user login.
- Separate role permissions: only Admin can open the analysis report page.
- Purple/violet responsive dashboard, analytics graph gallery, and logout.
- Passwords for registered users are stored as password hashes in `users/users.json` (not plain text).

Run the web app:
```powershell
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

Default local admin credentials (for college demonstration only; change before any real deployment):
- Email: `admin@cybersecure.local`
- Password: `ChangeMe123!`

For deployment, set `FLASK_SECRET_KEY`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` environment variables. This is a student demonstration app; do not expose it publicly without additional security review.
