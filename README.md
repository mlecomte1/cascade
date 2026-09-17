# Cascade

Desktop decoder, 100% offline. Session memory only — no history, no network, no database.

## Sur le PC (sans Python)

Un seul fichier : `dist\Cascade.exe` (copie aussi sur le Bureau).

Double-clic, ou copie-le où tu veux (Bureau, USB, autre dossier). Pas besoin de Python ni du projet.

Pour le régénérer après un changement :

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build-windows.ps1
```

## Lancer depuis le code source

Windows : double-clic sur `Cascade.bat`, ou :

```powershell
C:\Users\mathi\Documents\Projet\decoder\Cascade.bat
```

Debian :

```bash
sudo apt install libxcb-cursor0 libegl1   # une fois
bash cascade.sh
```

Le premier lancement crée le venv et installe les dépendances. Les suivants ouvrent juste la fenêtre.

## Package

- Windows portable exe: `packaging/build-windows.ps1` → `dist/Cascade.exe`
- Debian `.deb` (à lancer **sur Debian**): `bash packaging/build-debian.sh`

QR / LSB : **Ouvrir un fichier** image, puis laisser Auto lire le QR ou le LSB.
