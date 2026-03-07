# 📂 input/

Drop your exported Windows registry hive files here before running the audit.

## Required Files

| File | Description |
|------|-------------|
| `SAM` | Exported SAM registry hive |
| `SYSTEM` | Exported SYSTEM registry hive |

## How to Export on Windows (Run as Administrator)

Open **Command Prompt as Administrator** on the target Windows machine and run:

```cmd
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
```

Then transfer both files into this `input/` folder on your audit machine.

## Transfer Methods

**Using SCP (from Kali/Linux):**
```bash
scp user@192.168.1.x:C:/Users/Public/SAM ./input/SAM
scp user@192.168.1.x:C:/Users/Public/SYSTEM ./input/SYSTEM
```

**Using USB / shared folder:**
Simply copy and paste the files into this folder.

---

> ⚠️ Never commit SAM or SYSTEM files to GitHub — they are blocked by .gitignore
