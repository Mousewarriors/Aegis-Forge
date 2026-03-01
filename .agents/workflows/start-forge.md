---
description: How to start the Aegis Forge application (Backend and Frontend)
---

To start Aegis Forge, follow the authoritative instructions in **[STARTUP.md](../../STARTUP.md)**.

### Summary of Commands:

1. **Terminal 1 (Backend):**
   ```powershell
   cd backend
   .\venv\Scripts\activate
   python main.py
   ```

2. **Terminal 2 (Frontend):**
   ```powershell
   cd frontend
   npx next dev -p 3000 --hostname 0.0.0.0
   ```
