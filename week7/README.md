# Config‑Driven Backup Planner (Dry‑Run Simulator)

A Python‑based, configuration‑driven **backup planning tool** that validates backup configurations, simulates backup behavior, and produces human‑readable dry‑run reports — all without performing any real file operations.

This tool is designed for learning **schema design**, **validation**, **software architecture**, and **simulation logic**.

---

# ✅ Overview

The Backup Planner reads a JSON configuration file and:

1. **Validates** it through a four‑level validation system  
2. **Simulates** realistic backup operations using fake filenames and sizes  
3. **Generates** a complete, formatted dry‑run report  
4. Ensures **no real files** are ever touched (dry‑run only)

This makes it perfect for testing backup logic safely.

---

# ✅ Usage

### Run the backup planner with a configuration file:

```bash
python backup_planner.py backup_config.json