<div align="center">
    <img src="https://raw.githubusercontent.com/JavierOlmedo/AppLockerEnum/main/assets/logo.png">
</div>

# AppLockerEnum 🛡️🔍

A lightweight **AppLocker policy enumerator** for red team ops, auditing, and detection labs.  
Reads HKLM registry keys (`SrpV2`), parses XML rules, and exports to CSV for easy analysis.

---

## ✨ Features

- Enumerates AppLocker collections: `Exe`, `Msi`, `Script`, `Dll`, `Appx`
- Checks both registry views: `Registry64` and `Registry32`
- Supports `--raw-xml`, `--csv [path]`, `--csv-append`, `--csv-compact`
- Outputs clean summaries + optional XML dump
- CSV export is SIEM-friendly (escaped and normalized)

---

## ⚙️ Requirements

- Windows (x64 preferred)
- .NET Framework 4.8
- Read access to HKLM (Admin recommended)
- `AppIDSvc` service should be **Running** if you want enforcement info

---

## 🛠️ Build

Open the solution in **Visual Studio** (target `.NET Framework 4.8`)  
or compile manually:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /t:exe /out:AppLockerEnum.exe Program.cs
```

## 🚀 Usage

```powershell
# Basic enumeration
.\AppLockerEnum.exe

# Export to CSV (compact mode)
.\AppLockerEnum.exe --csv out.csv --csv-compact

# Append results to existing CSV
.\AppLockerEnum.exe --csv out.csv --csv-append

# Include raw XML in console output
.\AppLockerEnum.exe --raw-xml
```

## 🎬 Demo

See `assets/demo.gif` for a quick usage example

## 🤝 Contributing

Pull requests welcome — keep compatibility with .NET Framework 4.8 and Windows x64.
Focus on clarity, stability, and stealth-friendly output.

## 📜 License

This project is licensed under the MIT © [Javier Olmedo](https://github.com/JavierOlmedo)

<div align="center"> Made with ❤️ in Spain </div>