# csct (Cyber Security & Cyber Insurance Toolkit)

Monorepo containing two subprojects:

## 1) cyber_security_score
Cyber security scoring model and Web App for cybersecurity scoring.
- `cyber_security_score.py`, `single_target_cyber_score.py`.
- Create venv under `cyber_security_score/venv` and `pip install -r requirement.txt`.
- Run in VS Code with the interpreter set to `cyber_security_score/venv/bin/python`.

## 2) cyber_insurance_modeling
Cyber insurance premium pricing models 
- `Cyber_Pricing_v1.5_2PremiumPrinciples.py`
- Create venv under `cyber_insurance_modeling/venv` and install `scipy numpy pandas matplotlib jupyter black flake8` (or `pip install -r requirements.txt` if present).
- Run in VS Code with the interpreter set to `cyber_insurance_modeling/venv/bin/python`.

## Dev notes
- Each subproject is self-contained with its own venv and VS Code settings.
