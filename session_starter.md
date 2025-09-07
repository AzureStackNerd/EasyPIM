# EasyPIM Session Starter

## 🚨 **CRITICAL TAG FORMAT REQUIREMENTS** 🚨

# ⚠️ **DO NOT FORGET TAG FORMATS!!!** ⚠️

### **EasyPIM Core Module Tags:**
```
core-vX.Y.Z
```
**Examples:** `core-v2.0.19`, `core-v2.1.0`

### **EasyPIM Orchestrator Module Tags:**
```
orchestrator-vX.Y.Z
```
**Examples:** `orchestrator-v1.3.4`, `orchestrator-v1.4.0`

### **GitHub Actions Triggers:**
- **core-v*** triggers `build-core-tag.yml` workflow
- **orchestrator-v*** triggers `build-orchestrator.yml` workflow
- **v*** (without prefix) triggers `build.yml` but is DEPRECATED - use core-v instead!

## ⚠️ **NEVER USE PLAIN v* TAGS FOR CORE MODULE!** ⚠️

---

## 🧠 **Assistant Memory & Context**

### **Current State (2025-09-07)**
- **EasyPIM Core**: v2.0.19 (tagged as `core-v2.0.19`)
- **EasyPIM.Orchestrator**: v1.3.4 (tagged as `orchestrator-v1.3.4`)
- **Branch**: `main` (feature branch was merged)
- **Major Feature**: Comprehensive principal validation to prevent 400 Bad Request errors

### **Key Technical Achievements**
- ✅ **Root Cause Resolved**: Invalid principal IDs causing ARM API 400 Bad Request errors
- ✅ **Regex-based GUID Validation**: Extracts and validates ALL principals before API calls
- ✅ **Business Rules Engine**: Handles MFA/Authentication Context conflicts automatically
- ✅ **Early Error Detection**: Clear messages instead of mysterious API failures
- ✅ **Performance Optimized**: HashSet-based validation with scope filtering

### **Module Architecture**
- **EasyPIM Core**: Individual PIM functions, backup/restore, basic policies
- **EasyPIM.Orchestrator**: Configuration management via `Invoke-EasyPIMOrchestrator`
- **Key Function**: `Test-PIMPolicyBusinessRules` for conflict resolution
- **Validation Flow**: Principal validation → Policy processing → Assignment operations

### **Publishing Workflow**
1. Bump versions in `.psd1` files
2. Create correct tags: `core-vX.Y.Z` and `orchestrator-vX.Y.Z`
3. Push tags to trigger GitHub Actions
4. Monitor PowerShell Gallery publication

---

## 🎯 **Project Overview**

**EasyPIM** - PowerShell module for Microsoft Entra PIM management with two-module architecture

### **Key Functions to Remember**
- `Invoke-EasyPIMOrchestrator`: Main orchestration function
- `Test-PIMPolicyBusinessRules`: Handles policy conflicts
- `Get-EasyPIMConfiguration`: Loads from file or Key Vault (in Orchestrator module)
- `Test-PrincipalExists`: Validates principal existence

### **Testing**
- Run `.\tests\pester.ps1 -TestGeneral $true -TestFunctions $false -Output Normal -Fast`
- All 7011+ tests should pass
- General tests cover file integrity, manifests, PSScriptAnalyzer

### **Common Issues**
- **400 Bad Request**: Usually invalid principal IDs → now caught by validation
- **MFA vs Auth Context**: Conflicts automatically resolved by business rules
- **Module Loading**: Always force reload after changes: `Import-Module -Force`

---

## 📅 **Recent Session Log**

| Date | Key Achievement |
|------|-----------------|
| 2025-09-07 | ✅ Principal validation prevents 400 Bad Request errors |
| 2025-09-07 | ✅ Correct tag formats: core-v2.0.19, orchestrator-v1.3.4 |
| 2025-09-07 | ✅ Business rules engine for policy conflicts |
| 2025-09-07 | ✅ Comprehensive GUID validation with scope filtering |
