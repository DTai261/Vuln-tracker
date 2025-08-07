# Burp Suite Vuln Tracker Extension

A comprehensive Burp Suite extension for vulnerability management, path monitoring, and audit tracking during penetration testing. This extension streamlines the vulnerability discovery and documentation process with advanced project management capabilities.

## Features

### 🎯 Vulnerability Management
- **CWE Classification** - Mark vulnerabilities with 15+ CWE categories (SQL Injection, XSS, Command Injection, etc.)
- **Dual Interface** - CWE Tracker tab for quick marking + traditional right-click context menu
- **Request-specific View** - See all vulnerabilities for the current request instantly
- **Advanced Filtering** - Filter vulnerabilities by CWE type for focused analysis
- **Multiple Export Formats** - Export to JSON, CSV, or plain text for reporting
- **Duplicate Prevention** - Automatic detection and prevention of duplicate vulnerability entries
- **Timestamp Tracking** - Complete audit trail with vulnerability discovery timestamps

### 📊 Project Management
- **Multi-Project Support** - Manage separate vulnerability databases for different engagements
- **Project Switching** - Quick switching between projects with automatic data isolation
- **Data Persistence** - Automatic saving with JSON-based database storage
- **Project Statistics** - Real-time statistics showing vulnerability counts and audit progress
- **Data Migration** - Easy migration of data between projects and file locations

### 🔍 Path Monitoring & Watch Lists
- **Smart Watch Lists** - Monitor specific endpoints with audit status tracking
- **Pattern Matching** - Support for wildcards and regex patterns in path matching
- **Auto-Highlighting** - Automatic request highlighting in Proxy, Scanner, and Spider
- **Audit Status Tracking** - Mark paths as audited manually or automatically
- **Bulk Operations** - Mark all paths as audited, clear lists, import/export functionality
- **Progress Tracking** - Visual progress indicators showing audit completion status

### 🗺️ Sitemap Integration
- **Automated Import** - Import endpoints directly from Burp's Target sitemap
- **Advanced Filtering** - Exclude by file extensions, MIME types, or custom patterns
- **MIME Type Detection** - Intelligent MIME type filtering with preset configurations
- **Live Monitoring** - Real-time monitoring of sitemap changes with automatic updates
- **Target Selection** - Choose specific hosts/scopes for endpoint import
- **Batch Processing** - Process large sitemaps efficiently with filtering options

### ⚙️ Configuration & Automation
- **Auto-Audit Settings** - Automatically mark paths as audited when accessed via Repeater/Scanner
- **Configurable Monitoring** - Adjustable sitemap monitoring frequency (Fast/Normal/Slow)
- **Preset Filters** - Pre-configured MIME type filters for static assets and API responses
- **Flexible Configuration** - Comprehensive settings dialog for all extension features
- **Import/Export Settings** - Save and restore configuration across different environments

## Installation

1. **Download the Extension**
   - Download `vuln_tracker.py` from this repository

2. **Load in Burp Suite**
   - Go to `Extender` → `Extensions`
   - Click `Add`
   - Select `Python` as extension type
   - Select the `vuln_tracker.py` file
   - Click `Next` and then `Close`

3. **Verify Installation**
   - Look for the "Vuln tracker" tab in the main Burp interface
   - The extension will automatically create a default project on first run

## Quick Start Guide

### 1. Project Setup
- The extension automatically creates a default project on first run
- Access project management via the `Projects` button in the main interface
- Switch between projects or create new ones as needed for different engagements

### 2. Vulnerability Tracking
#### Using the CWE Tracker Tab:
1. **Navigate to any request** in Repeater, Proxy History, or Target
2. **Click the "Vuln Tracker" tab** (appears next to Pretty/Raw/Hex)
3. **Select a CWE type** from the dropdown menu
4. **Click "Mark Vulnerability"** to record the finding
5. **View request-specific vulnerabilities** in the same tab

#### Using Context Menu:
1. **Right-click any request** in Proxy History, Target, or Repeater
2. **Select "Mark as Vulnerable"** 
3. **Choose the appropriate CWE type**
4. **View all vulnerabilities** in the main "Vulnerabilities" tab

### 3. Watch List Management
1. **Navigate to the "Watch List" tab** in the main interface
2. **Add paths manually** using the text area or "Add Path" button
3. **Import from sitemap** using the "Import from Sitemap" button
4. **Configure auto-highlighting** and audit tracking options
5. **Mark paths as audited** as you complete testing

### 4. Sitemap Integration
1. **Click "Import from Sitemap"** in the Watch List tab
2. **Select target hosts** and configure filtering options
3. **Set MIME type exclusions** (e.g., images, CSS, JS)
4. **Enable auto-monitoring** for real-time sitemap updates
5. **Import filtered endpoints** directly to your watch list

### 5. Configuration & Settings
1. **Click the "Configure" button** for advanced settings
2. **Set auto-audit preferences** for Repeater/Scanner integration
3. **Configure sitemap monitoring** frequency and filters
4. **Export/import settings** for team collaboration

## Supported CWE Categories

The extension supports comprehensive vulnerability classification with the following CWE types:

- **CWE-22** - Path Traversal
- **CWE-78** - OS Command Injection  
- **CWE-79** - Cross-Site Scripting (XSS)
- **CWE-89** - SQL Injection
- **CWE-90** - LDAP Injection
- **CWE-91** - XML Injection
- **CWE-94** - Code Injection
- **CWE-95** - Dynamic Code Evaluation
- **CWE-98** - File Inclusion
- **CWE-200** - Information Disclosure
- **CWE-284** - Access Control Issues
- **CWE-287** - Authentication Bypass
- **CWE-352** - Cross-Site Request Forgery
- **CWE-434** - File Upload Issues
- **CWE-601** - Open Redirect
- **CWE-862** - Missing Authorization

## Export Formats

### JSON Export
Complete vulnerability data with metadata:
```json
{
  "1": {
    "cwe": "CWE-89",
    "description": "SQL Injection",
    "url": "https://example.com/api/users",
    "method": "POST",
    "timestamp": "2025-01-15 14:30:22",
    "request_hash": "abc123"
  }
}
```

### CSV Export
Structured data for spreadsheet analysis:
```csv
CWE,Description,Method,URL,Timestamp,Request_Hash
CWE-89,SQL Injection,POST,https://example.com/api/users,2025-01-15 14:30:22,abc123
```

### Text Export
Simple URL list for tools integration:
```
https://example.com/api/users
https://example.com/admin/panel
```

## Advanced Features

### Pattern Matching
- **Wildcard Support**: Use `*` for flexible path matching
  - `/api/*/users` matches `/api/v1/users`, `/api/v2/users`
  - `/admin/*` matches any path starting with `/admin/`
- **Regex Support**: Advanced pattern matching for complex scenarios
- **Substring Matching**: Simple contains-based matching for convenience

### Auto-Audit Integration
- **Repeater Integration**: Automatically mark paths as audited when tested in Repeater
- **Scanner Integration**: Mark paths as audited when scanned by Burp Scanner
- **Visual Feedback**: Real-time notifications when auto-audit triggers
- **Configurable**: Enable/disable auto-audit per tool

### MIME Type Filtering
- **Intelligent Detection**: Uses Burp's MIME type detection
- **Preset Configurations**: 
  - Static Assets (CSS, JS, Images)
  - API Responses (JSON, XML)
- **Custom Exclusions**: Define your own MIME type filters
- **Content-Type Fallback**: Secondary detection via HTTP headers

### Project Isolation
- **Separate Databases**: Each project maintains independent vulnerability data
- **Quick Switching**: Change projects without losing context
- **Data Portability**: Export/import project data between environments
- **Backup Support**: Automatic data persistence with manual backup options

## Tips & Best Practices

1. **Start with Sitemap Import**: Use sitemap integration to quickly populate your watch list
2. **Use Project Separation**: Create separate projects for different clients/applications
3. **Enable Auto-Audit**: Reduce manual overhead by enabling auto-audit for Repeater/Scanner
4. **Regular Exports**: Export vulnerability data frequently for backup and reporting
5. **Pattern Optimization**: Use specific patterns to reduce false positives in highlighting
6. **MIME Filtering**: Exclude static assets to focus on dynamic endpoints

## Troubleshooting

### Common Issues
- **Extension not loading**: Ensure Python support is enabled in Burp
- **Data not persisting**: Check file permissions in the extension directory
- **Slow performance**: Reduce sitemap monitoring frequency in settings
- **Missing vulnerabilities**: Verify project selection and data file location

### Performance Tips
- **Limit watch list size**: Large watch lists can impact performance
- **Use specific patterns**: Avoid overly broad wildcard patterns
- **Regular cleanup**: Remove completed/irrelevant projects periodically
- **Monitor memory usage**: Large vulnerability datasets may require more memory

## File Structure

- `vuln_tracker.py` - Main extension file
- `README.md` - This documentation
- `INSTALLATION_GUIDE.md` - Detailed setup instructions
- `path_highlighter_data.json` - Default project data file
- `default_paths.txt` - Sample path configurations