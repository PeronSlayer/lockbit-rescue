LockBit Rescue - Windows quick start
====================================

Recommended path
----------------
Use the release asset named lockbit-wizard.exe. It starts the guided wizard and asks for the encrypted source folder, the output folder, and the recovery mode.

Important notes
---------------
- Keep the encrypted originals untouched. The tool reads from the source folder and writes recovered files to a separate output folder.
- Run the tool from a folder where you have write permission.
- If Windows Defender or SmartScreen warns about an unsigned executable, choose whether to continue only after verifying the release checksum from SHA256SUMS.txt.
- The Windows wizard can use a WSL/Linux backend for the actual recovery tools. Install WSL if the wizard reports that the backend is missing.

Release files
-------------
- lockbit-wizard.exe: standalone guided launcher for non-expert use.
- lockbit-rescue-windows-<version>.zip: full Windows package with scripts and documentation.
- SHA256SUMS.txt: SHA-256 checksums for release assets.

Checksum verification in PowerShell
-----------------------------------
Run this from the folder containing the downloaded files:

    Get-FileHash .\lockbit-wizard.exe -Algorithm SHA256

Compare the Hash value with the matching line in SHA256SUMS.txt.

Fallback without the executable
-------------------------------
If you do not want to run the executable, open Command Prompt in the extracted zip folder and run:

    lockbit-wizard.cmd

If Python is installed, the launcher will run lockbit-wizard.py directly.
