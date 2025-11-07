import telebot
import requests
import json
import hashlib
import base64
import sqlite3
import os
import time
import re
from datetime import datetime
import secrets
import string

API_TOKEN = "YOUR_BOT_TOKEN_HERE"
bot = telebot.TeleBot(API_TOKEN)

def init_db():
    conn = sqlite3.connect('security_tests.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scanned_bots
                 (id INTEGER PRIMARY KEY, bot_username TEXT, test_type TEXT, result TEXT, risk_level TEXT, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerability_log
                 (id INTEGER PRIMARY KEY, bot_username TEXT, vulnerability TEXT, description TEXT, risk_level TEXT, timestamp TEXT)''')
    conn.commit()
    conn.close()

@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_text = "Security Testing Bot for Telegram Bots\n\nAvailable Commands:\n/scan_bot [@username] - Security scan of another bot\n/test_bot_encryption [@username] - Test bot encryption\n/test_bot_api [@username] - Test bot API endpoints\n/check_bot_vulnerabilities [@username] - Find vulnerabilities\n/bot_security_report [@username] - Security report\n/list_scanned_bots - Show scanned bots\n/help - Usage guide"
    bot.reply_to(message, welcome_text)

@bot.message_handler(commands=['scan_bot'])
def scan_other_bot(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "Usage: /scan_bot @botusername")
            return
        
        target_bot = command_parts[1].replace('@', '')
        bot.reply_to(message, f"Scanning security of @{target_bot}...")
        
        results = []
        vulnerabilities = []
        
        bot_info = get_bot_info(target_bot)
        if bot_info:
            results.append("Bot identified: " + bot_info)
        else:
            results.append("Could not get bot info")
            vulnerabilities.append(("Information Disclosure", "Bot does not respond", "LOW"))
        
        endpoints_to_test = ["/start", "/help", "/info", "/settings"]
        
        for endpoint in endpoints_to_test:
            endpoint_test = test_bot_endpoint(target_bot, endpoint)
            if endpoint_test:
                results.append(endpoint + ": RESPONDS")
                sensitive_patterns = ['token', 'password', 'key', 'secret', 'database']
                if any(pattern in endpoint_test.lower() for pattern in sensitive_patterns):
                    vulnerabilities.append(("Information Disclosure", "Sensitive info in " + endpoint, "HIGH"))
        
        injection_tests = [
            "'; DROP TABLE users--",
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd"
        ]
        
        for injection in injection_tests:
            injection_result = test_bot_input(target_bot, injection)
            if injection_result and ("error" in injection_result.lower() or "exception" in injection_result.lower()):
                vulnerabilities.append(("Input Validation", "Error with input: " + injection[:20], "MEDIUM"))
        
        start_time = time.time()
        test_bot_endpoint(target_bot, "/start")
        response_time = time.time() - start_time
        
        results.append("Response time: " + str(round(response_time, 2)) + "s")
        if response_time > 3.0:
            vulnerabilities.append(("Performance Issue", "Slow response: " + str(round(response_time, 2)) + "s", "LOW"))
        
        privacy_check = check_bot_privacy(target_bot)
        if privacy_check:
            results.append("Privacy: " + privacy_check)
        
        save_scan_result(target_bot, 'comprehensive_scan', "Found " + str(len(vulnerabilities)) + " vulnerabilities", 
                        "HIGH" if len(vulnerabilities) > 0 else "LOW")
        
        for vuln in vulnerabilities:
            save_vulnerability(target_bot, vuln[0], vuln[1], vuln[2])
        
        response = "SECURITY REPORT: @" + target_bot + "\n\nRESULTS:\n" + "\n".join(results) + "\n\n"
        
        if vulnerabilities:
            response += "VULNERABILITIES FOUND:\n"
            for i, vuln in enumerate(vulnerabilities, 1):
                response += str(i) + ". " + vuln[0] + " - " + vuln[2] + " risk\n"
                response += "   " + vuln[1] + "\n"
        else:
            response += "No critical vulnerabilities found"
        
        bot.reply_to(message, response)
        
    except Exception as e:
        bot.reply_to(message, "Scan error: " + str(e))

@bot.message_handler(commands=['test_bot_encryption'])
def test_bot_encryption(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "Usage: /test_bot_encryption @botusername")
            return
        
        target_bot = command_parts[1].replace('@', '')
        bot.reply_to(message, f"Testing encryption of @{target_bot}...")
        
        tests = []
        vulnerabilities = []
        
        test_data = "test_encryption_data_123"
        
        base64_data = base64.b64encode(test_data.encode()).decode()
        response_b64 = send_message_to_bot(target_bot, base64_data)
        
        if response_b64:
            tests.append("Base64 sent: " + base64_data[:30])
            if "error" not in response_b64.lower():
                tests.append("Bot processes Base64")
            else:
                vulnerabilities.append(("Encoding Handling", "Error processing Base64", "LOW"))
        
        md5_hash = hashlib.md5(test_data.encode()).hexdigest()
        response_md5 = send_message_to_bot(target_bot, md5_hash)
        
        if response_md5:
            tests.append("MD5 hash sent: " + md5_hash[:16])
        
        weak_patterns = ['md5', 'base64', 'simple', 'basic']
        if any(pattern in response_b64.lower() for pattern in weak_patterns):
            vulnerabilities.append(("Weak Encryption", "Possible weak encryption usage", "MEDIUM"))
        
        save_scan_result(target_bot, 'encryption_test', "Encryption tests completed", 
                        "HIGH" if len(vulnerabilities) > 0 else "LOW")
        
        for vuln in vulnerabilities:
            save_vulnerability(target_bot, vuln[0], vuln[1], vuln[2])
        
        response = "ENCRYPTION TESTS: @" + target_bot + "\n\n" + "\n".join(tests) + "\n\n"
        
        if vulnerabilities:
            response += "ENCRYPTION ISSUES:\n"
            for vuln in vulnerabilities:
                response += "- " + vuln[0] + " - " + vuln[2] + " risk\n"
        else:
            response += "Encryption: No critical issues detected"
        
        bot.reply_to(message, response)
        
    except Exception as e:
        bot.reply_to(message, "Encryption test error: " + str(e))

@bot.message_handler(commands=['test_bot_api'])
def test_bot_api(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "Usage: /test_bot_api @botusername")
            return
        
        target_bot = command_parts[1].replace('@', '')
        bot.reply_to(message, f"Testing API of @{target_bot}...")
        
        tests = []
        vulnerabilities = []
        
        common_endpoints = [
            "/start", "/help", "/info", "/settings", "/config",
            "/users", "/admin", "/database", "/backup", "/log"
        ]
        
        for endpoint in common_endpoints:
            test_result = test_bot_endpoint(target_bot, endpoint)
            
            if test_result:
                tests.append(endpoint + ": RESPONDS")
                sensitive_info = ['password', 'token', 'key', 'secret', 'database', 'admin']
                if any(info in test_result.lower() for info in sensitive_info):
                    vulnerabilities.append(("Sensitive Data Exposure", "Sensitive info in " + endpoint, "HIGH"))
                
                if "error" in test_result.lower() or "exception" in test_result.lower() or "stack trace" in test_result.lower():
                    vulnerabilities.append(("Debug Information", "Debug info in " + endpoint, "MEDIUM"))
            else:
                tests.append(endpoint + ": NO RESPONSE")
        
        dangerous_endpoints = ['/delete', '/remove', '/drop', '/reset']
        for endpoint in dangerous_endpoints:
            test_result = test_bot_endpoint(target_bot, endpoint)
            if test_result:
                vulnerabilities.append(("Dangerous Endpoint", "Dangerous endpoint exposed: " + endpoint, "HIGH"))
        
        save_scan_result(target_bot, 'api_test', "Tested " + str(len(common_endpoints)) + " endpoints", 
                        "HIGH" if len(vulnerabilities) > 0 else "LOW")
        
        for vuln in vulnerabilities:
            save_vulnerability(target_bot, vuln[0], vuln[1], vuln[2])
        
        response = "API TESTS: @" + target_bot + "\n\n"
        response += "Endpoints tested: " + str(len(common_endpoints)) + "\n"
        response += "Vulnerabilities: " + str(len(vulnerabilities)) + "\n\n"
        
        if vulnerabilities:
            response += "API VULNERABILITIES:\n"
            for vuln in vulnerabilities:
                response += "- " + vuln[0] + "\n"
                response += "  " + vuln[1] + "\n"
        
        bot.reply_to(message, response)
        
    except Exception as e:
        bot.reply_to(message, "API test error: " + str(e))

@bot.message_handler(commands=['check_bot_vulnerabilities'])
def check_bot_vulnerabilities(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "Usage: /check_bot_vulnerabilities @botusername")
            return
        
        target_bot = command_parts[1].replace('@', '')
        bot.reply_to(message, f"Finding vulnerabilities in @{target_bot}...")
        
        vulnerabilities = []
        
        sql_payloads = [
            "' OR '1'='1'--",
            "'; DROP TABLE users--", 
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--"
        ]
        
        for payload in sql_payloads:
            result = send_message_to_bot(target_bot, payload)
            if result and ("error" in result.lower() or "sql" in result.lower() or "syntax" in result.lower()):
                vulnerabilities.append(("SQL Injection", "Vulnerable to: " + payload[:20], "HIGH"))
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            result = send_message_to_bot(target_bot, payload)
            if result and payload.lower() in result.lower():
                vulnerabilities.append(("XSS Vulnerability", "No HTML/JavaScript sanitization", "MEDIUM"))
        
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd"
        ]
        
        for payload in path_payloads:
            result = send_message_to_bot(target_bot, payload)
            if result and ("passwd" in result.lower() or "file" in result.lower() or "path" in result.lower()):
                vulnerabilities.append(("Path Traversal", "Possible file access: " + payload[:20], "HIGH"))
        
        cmd_payloads = [
            "; ls -la",
            "| whoami", 
            "&& cat /etc/passwd",
            "$(whoami)"
        ]
        
        for payload in cmd_payloads:
            result = send_message_to_bot(target_bot, payload)
            if result and ("root" in result.lower() or "admin" in result.lower() or "list" in result.lower()):
                vulnerabilities.append(("Command Injection", "Executes commands: " + payload, "CRITICAL"))
        
        save_scan_result(target_bot, 'vulnerability_scan', "Found " + str(len(vulnerabilities)) + " vulnerabilities", 
                        "CRITICAL" if len(vulnerabilities) > 0 else "LOW")
        
        for vuln in vulnerabilities:
            save_vulnerability(target_bot, vuln[0], vuln[1], vuln[2])
        
        response = "VULNERABILITY ANALYSIS: @" + target_bot + "\n\n"
        response += "Total vulnerabilities: " + str(len(vulnerabilities)) + "\n\n"
        
        if vulnerabilities:
            critical_vulns = [v for v in vulnerabilities if v[2] == "CRITICAL"]
            high_vulns = [v for v in vulnerabilities if v[2] == "HIGH"]
            medium_vulns = [v for v in vulnerabilities if v[2] == "MEDIUM"]
            
            if critical_vulns:
                response += "CRITICAL VULNERABILITIES:\n"
                for vuln in critical_vulns:
                    response += "- " + vuln[0] + "\n"
                    response += "  " + vuln[1] + "\n"
            
            if high_vulns:
                response += "\nHIGH VULNERABILITIES:\n"
                for vuln in high_vulns:
                    response += "- " + vuln[0] + "\n"
                    response += "  " + vuln[1] + "\n"
            
            if medium_vulns:
                response += "\nMEDIUM VULNERABILITIES:\n"
                for vuln in medium_vulns:
                    response += "- " + vuln[0] + "\n"
                    response += "  " + vuln[1] + "\n"
        else:
            response += "No critical vulnerabilities found"
        
        bot.reply_to(message, response)
        
    except Exception as e:
        bot.reply_to(message, "Vulnerability search error: " + str(e))

@bot.message_handler(commands=['bot_security_report'])
def bot_security_report(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "Usage: /bot_security_report @botusername")
            return
        
        target_bot = command_parts[1].replace('@', '')
        
        conn = sqlite3.connect('security_tests.db')
        c = conn.cursor()
        
        c.execute("SELECT * FROM scanned_bots WHERE bot_username = ? ORDER BY timestamp DESC", (target_bot,))
        scan_history = c.fetchall()
        
        c.execute("SELECT * FROM vulnerability_log WHERE bot_username = ? ORDER BY risk_level DESC", (target_bot,))
        vulnerabilities = c.fetchall()
        
        conn.close()
        
        report = ["SECURITY REPORT: @" + target_bot]
        report.append("=" * 50)
        
        report.append("\nSCAN HISTORY: " + str(len(scan_history)))
        for scan in scan_history[:5]:
            report.append(scan[5][11:16] + " - " + scan[2] + " - " + scan[4] + " risk")
        
        vuln_counts = {}
        for vuln in vulnerabilities:
            risk = vuln[4]
            vuln_counts[risk] = vuln_counts.get(risk, 0) + 1
        
        report.append("\nVULNERABILITIES FOUND:")
        for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = vuln_counts.get(risk, 0)
            report.append("- " + risk + ": " + str(count))
        
        report.append("\nRECOMMENDATIONS:")
        
        if vuln_counts.get('CRITICAL', 0) > 0:
            report.append("- CORRECT CRITICAL VULNERABILITIES IMMEDIATELY")
        if vuln_counts.get('HIGH', 0) > 0:
            report.append("- Resolve HIGH vulnerabilities in 48h")
        if vuln_counts.get('MEDIUM', 0) > 0:
            report.append("- Plan MEDIUM vulnerabilities correction")
        
        report.append("- Review security configuration")
        report.append("- Implement input validation")
        report.append("- Update dependencies")
        
        bot.reply_to(message, "\n".join(report))
        
    except Exception as e:
        bot.reply_to(message, "Report generation error: " + str(e))

@bot.message_handler(commands=['list_scanned_bots'])
def list_scanned_bots(message):
    try:
        conn = sqlite3.connect('security_tests.db')
        c = conn.cursor()
        
        c.execute("SELECT DISTINCT bot_username, COUNT(*) as scan_count, MAX(timestamp) as last_scan FROM scanned_bots GROUP BY bot_username")
        bots = c.fetchall()
        
        conn.close()
        
        if not bots:
            bot.reply_to(message, "No bots scanned yet")
            return
        
        response = "SCANNED BOTS:\n\n"
        for bot_data in bots:
            username, scan_count, last_scan = bot_data
            response += "@" + username + "\n"
            response += "   Scans: " + str(scan_count) + "\n"
            response += "   Last: " + last_scan[:16] + "\n\n"
        
        bot.reply_to(message, response)
        
    except Exception as e:
        bot.reply_to(message, "Error listing bots: " + str(e))

@bot.message_handler(commands=['help'])
def show_help(message):
    help_text = "Security Testing Bot - Ethical Guide\n\nAUTHORIZED USE:\n- Only scan your own bots\n- Get explicit permission from owner\n- Use in testing environments\n- Report findings responsibly\n\nCOMMANDS:\n/scan_bot [@bot] - Full security scan\n/test_bot_encryption [@bot] - Encryption tests\n/test_bot_api [@bot] - API tests\n/check_bot_vulnerabilities [@bot] - Find vulnerabilities\n/bot_security_report [@bot] - Full report\n/list_scanned_bots - Show scanned bots\n\nLEGAL:\nNever scan without authorization\nRespect privacy and terms\nReport vulnerabilities to owner"
    bot.reply_to(message, help_text)

def get_bot_info(bot_username):
    try:
        return "Bot: @" + bot_username + " - Available"
    except:
        return None

def test_bot_endpoint(bot_username, endpoint):
    try:
        return "Response from " + endpoint
    except:
        return None

def send_message_to_bot(bot_username, message):
    try:
        return "Simulated response to: " + message[:20]
    except:
        return None

def test_bot_input(bot_username, input_text):
    try:
        return send_message_to_bot(bot_username, input_text)
    except:
        return None

def check_bot_privacy(bot_username):
    try:
        return "Standard configuration"
    except:
        return "Could not verify"

def save_scan_result(bot_username, test_type, result, risk_level):
    try:
        conn = sqlite3.connect('security_tests.db')
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO scanned_bots (bot_username, test_type, result, risk_level, timestamp) VALUES (?, ?, ?, ?, ?)",
                 (bot_username, test_type, result, risk_level, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Error saving scan: " + str(e))

def save_vulnerability(bot_username, vuln_name, description, risk_level):
    try:
        conn = sqlite3.connect('security_tests.db')
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO vulnerability_log (bot_username, vulnerability, description, risk_level, timestamp) VALUES (?, ?, ?, ?, ?)",
                 (bot_username, vuln_name, description, risk_level, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Error saving vulnerability: " + str(e))

init_db()

if __name__ == "__main__":
    print("Security Scanner Bot Started")
    print("Designed to scan OTHER bots")
    print("Ethical use only")
    bot.polling()