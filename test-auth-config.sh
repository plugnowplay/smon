#!/bin/bash

# Quick Test Script for Changing Authentication Credentials
# This script demonstrates how to change username and password

echo "================================"
echo "Authentication Configuration Test"
echo "================================"
echo ""

# Backup current settings
echo "📋 Creating backup of current settings.json..."
cp settings.json settings.json.backup
echo "✓ Backup created: settings.json.backup"
echo ""

# Show current authentication config
echo "📝 Current authentication configuration:"
cat settings.json | jq '.authentication' 2>/dev/null || echo "Note: Install jq for pretty JSON output"
echo ""

# Example 1: Change to new credentials
echo "📌 Example 1: Changing to new credentials..."
echo "   New username: testadmin"
echo "   New password: TestPass@2025"
echo ""

# Create temporary settings with new credentials (for testing)
cp settings.json settings.json.test

# Manual example (since we can't modify in this script)
echo "To change credentials, edit settings.json and update:"
echo ""
echo '  "authentication": {'
echo '    "enabled": true,'
echo '    "username": "testadmin",     # <- Change this'
echo '    "password": "TestPass@2025", # <- Change this'  
echo '    "sessionTimeout": 86400000'
echo '  }'
echo ""

echo "Then restart the service:"
echo "  pm2 restart smon"
echo ""

# Show verification command
echo "📊 After restart, verify authentication in logs:"
echo "  pm2 logs smon | grep AUTH"
echo ""

# Restore original settings
echo "🔄 Restoring original settings..."
rm -f settings.json.test
echo "✓ Original settings restored"
echo ""

echo "✅ Test completed!"
echo ""
echo "Security Reminders:"
echo "  • Never share credentials"
echo "  • Use strong passwords (12+ chars with special chars)"
echo "  • Change password regularly (every 3 months)"
echo "  • Keep settings.json secure (not in version control)"
echo "  • Monitor auth logs for suspicious activity"
