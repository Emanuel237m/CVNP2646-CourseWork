Malware Behavior → MITRE ATT&CK Technique Mapper
A Python command‑line tool that analyzes observed malware behaviors and maps them to MITRE ATT&CK techniques using clear, rule‑based detection logic.
This project demonstrates blue‑team and detection‑engineering fundamentals, including behavior normalization, ATT&CK mapping, confidence scoring, and structured reporting.

🎯 Project Purpose
Security operations and detection teams analyze behavior, not just hashes or signatures.
This project shows how raw sandbox or telemetry data can be converted into MITRE ATT&CK‑aligned insights that are:

Deterministic
Explainable
Analyst‑friendly
Easy to extend


🧠 What the Tool Does

//Reads observed malware behaviors from JSON//
//Normalizes and models behaviors//
//Maps behaviors to MITRE ATT&CK techniques//
//Assigns confidence scores per mapping//
//Aggregates technique frequency//
//Outputs a structured analysis report in JSON//


📂 Project Structure
Plain Textweek14_mitre_mapper/├── data/│   ├── input_sample.json        # Sample malware behavior input│   ├── output_sample.json       # Expected output│   └── test_output.json         # Output generated from execution│├── src/│   ├── main.py                  # CLI entry point│   ├── models.py                # Behavior models & ATT&CK mapping logic│   └── utils.py                 # JSON input/output utilities│├── tests/├── README.md├── requirements.txt└── venv/Show more lines

📥 Input Format
JSON{  "sample_metadata": {    "sample_id": "MAL-2024-001",    "family": "ExampleRAT",    "analysis_date": "2024-03-15"  },  "observed_behaviors": [    {      "type": "api_call",      "value": "CreateRemoteThread",      "timestamp": "2024-03-15T14:23:10Z"    }  ]}Show more lines

📤 Output Format
JSON{  "sample_id": "MAL-2024-001",  "tagged_behaviors": [    {      "behavior": "CreateRemoteThread",      "mapped_techniques": ["T1055"],      "confidence": 0.9    }  ],  "technique_frequency": {    "T1055": 1  },  "summary": {    "total_behaviors_analyzed": 1,    "unique_techniques_detected": 1  }}Show more lines

▶️ How to Run
✅ Windows (Recommended)
1. Install Dependencies  & 2. Run the malware behavior mapper
  (1). py -m pip install -r requirements.txt
  (2). Be in the /src folder then run:  py main.py --input ../data/input_sample.json --output ../data/test_output.json

✅ macOS / Linux
1. Install Dependencies  & 2. Run the malware behavior mapper
  (1). python3 -m pip install -r requirements.txt
  (2). cd src
       python3 main.py --input ../data/input_sample.json --output ../data/test_output.json
✅ Verbose Logging (Optional)

🔍 Skills Demonstrated

Malware behavior analysis
MITRE ATT&CK framework usage
Detection engineering concepts
Secure Python development
CLI‑based security tooling
Explainable, rule‑based analytics


🚧 Future Improvements

Load full MITRE ATT&CK JSON dataset
Support multiple techniques per behavior
Export ATT&CK Navigator layer files
Add unit tests and CI
Integrate with dynamic malware analyzers


⚠️ Disclaimer
This project is for defensive security education and research only.
It does not execute malware or perform offensive actions.

📌 One‑Line Summary (for GitHub description)

Rule‑based malware behavior analysis tool that maps observed actions to MITRE ATT&CK techniques using explainable detection logic.