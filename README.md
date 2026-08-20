# 🛡️ MiniSIEM

A Java-based Mini Security Information and Event Management (SIEM) system designed for security log analysis, threat detection, alert generation, SQLite storage, and security reporting.

## 🚀 Features

- 🔍 Security log parsing
- 🚨 Automated threat detection
- 🔐 Failed login detection
- 🛡️ Repeated login failure detection
- 👤 Admin login monitoring
- 🌙 After-hours login detection
- 🌐 Suspicious IP detection
- 📊 Security dashboard
- 🗄️ SQLite database storage
- 📄 CSV security report generation
- 🧱 Object-Oriented Java architecture
- 📦 Maven dependency management

## 🏗️ Architecture

```text
Security Logs
     │
     ▼
┌──────────────┐
│ LogCollector │
└──────┬───────┘
       ▼
┌──────────────┐
│  LogParser   │
└──────┬───────┘
       ▼
┌──────────────┐
│   LogEvent   │
└──────┬───────┘
       ▼
┌──────────────┐
│  RuleEngine  │
└──────┬───────┘
       ▼
┌──────────────┐
│    Alert     │
└──────┬───────┘
       ▼
┌──────────────┐
│ SQLite DB    │
└──────┬───────┘
       │
       ├──────────────► Dashboard
       │
       └──────────────► CSV Report
