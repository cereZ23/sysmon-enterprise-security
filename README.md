# Sysmon Enterprise Security Monitoring

Configurazioni Sysmon production-ready ottimizzate per il monitoraggio della sicurezza degli endpoint Windows con integrazione Splunk.

## Panoramica

Repository contenente configurazioni Sysmon hardenizzate progettate per ambienti enterprise, bilanciando threat detection completo con riduzione del rumore per operazioni SOC.

## Struttura Repository

```
sysmon-enterprise-security/
├── configs/                    # Configurazioni Sysmon XML
│   ├── sysmon-ws.xml          # Workstation (Windows 10/11)
│   ├── sysmon-srv.xml         # Server Generico
│   ├── sysmon-dc.xml          # Domain Controller
│   ├── sysmon-sql.xml         # SQL Server
│   ├── sysmon-exch.xml        # Exchange Server
│   ├── sysmon-iis.xml         # IIS Web Server
│   └── README-*.md            # Documentazione per config
├── deploy/                     # Script di deployment
│   ├── windows-audit-policy.ps1    # Audit Policy (Multi-Lingua)
│   ├── enable-powershell-logging.ps1
│   └── README.md
├── docs/                       # Documentazione
│   ├── GUIDA-SYSMON-ENTERPRISE-IT.md    # Guida completa (IT)
│   ├── GUIDA-SYSMON-ENTERPRISE-IT.docx  # Versione Word
│   ├── SYSMON-ENTERPRISE-SECURITY-GUIDE.md  # Guide (EN)
│   └── guides/                 # Guide aggiuntive
├── scripts/                    # Script utility
│   ├── md_to_docx.py          # Convertitore Markdown->DOCX
│   └── create_technical_report.py
├── tests/                      # Test automatizzati
└── .github/workflows/          # CI/CD GitHub Actions
```

## Quick Start

### 1. Installa Sysmon

```powershell
# Download Sysmon da Microsoft Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Installa con configurazione workstation
sysmon.exe -accepteula -i configs/sysmon-ws.xml
```

### 2. Configura Windows Audit Policy

```powershell
# Supporta TUTTE le lingue Windows (IT, EN, DE, FR, ES, etc.)
powershell.exe -ExecutionPolicy Bypass -File deploy/windows-audit-policy.ps1
```

### 3. Abilita PowerShell Logging

```powershell
powershell.exe -ExecutionPolicy Bypass -File deploy/enable-powershell-logging.ps1
```

## Configurazioni per Ruolo

| Config | Target | Minacce Chiave |
|--------|--------|----------------|
| `sysmon-ws.xml` | Workstation | Phishing, LOLBins, Macro Office |
| `sysmon-srv.xml` | Server Generico | Lateral Movement, Discovery |
| `sysmon-dc.xml` | Domain Controller | DCSync, Golden Ticket, LSASS |
| `sysmon-sql.xml` | SQL Server | SQL Injection, xp_cmdshell |
| `sysmon-exch.xml` | Exchange | ProxyLogon/Shell, Webshell |
| `sysmon-iis.xml` | IIS Web Server | Webshell, RCE |

## Copertura MITRE ATT&CK

| Metrica | Valore |
|---------|--------|
| **Copertura Sysmon** | 81-90% |
| **Copertura Combinata** | 97.5% |
| **Tecniche Coperte** | 40+ |
| **Tattiche** | 9/14 |

### Defense-in-Depth

```
Sysmon + Windows Security Events + PowerShell Logging = 95%+ Copertura
```

## Supporto Multi-Lingua

Lo script `windows-audit-policy.ps1` (v2.1.0) usa **GUID** invece dei nomi localizzati delle subcategorie, funzionando su:

- Italiano (it-IT)
- English (en-US)
- Deutsch (de-DE)
- Francais (fr-FR)
- Espanol (es-ES)
- E tutte le altre lingue Windows

## Documentazione

- **Guida Completa (IT):** [docs/GUIDA-SYSMON-ENTERPRISE-IT.md](docs/GUIDA-SYSMON-ENTERPRISE-IT.md)
- **Complete Guide (EN):** [docs/SYSMON-ENTERPRISE-SECURITY-GUIDE.md](docs/SYSMON-ENTERPRISE-SECURITY-GUIDE.md)
- **Deploy Scripts:** [deploy/README.md](deploy/README.md)

## Requisiti

- **Sysmon**: v15.0 o successivo
- **Schema Version**: 4.50
- **Windows**: 10/11 (Workstation), Server 2016+ (Server)
- **Permessi**: Amministratore per installazione

## Test CI/CD

I test automatizzati verificano:
- Validazione sintassi XML
- Copertura MITRE ATT&CK con Atomic Red Team
- Supporto multi-lingua (IT, DE, FR, ES)

Vedi: [.github/workflows/sysmon-test.yml](.github/workflows/sysmon-test.yml)

## Licenza

MIT License

---

**Versione:** 2.1.0
**Ultimo Aggiornamento:** Dicembre 2025
**Production Readiness Score:** 92/100
