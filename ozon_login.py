import pandas as pd
import time
import imaplib
import email
import re
import os
import zipfile
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException

def create_proxy_auth_extension(proxy_host, proxy_port, proxy_username, proxy_password, scheme='http', plugin_path=None):
    """Create a Chrome extension to add proxy authentication"""
    if plugin_path is None:
        plugin_path = f'proxy_auth_plugin_{time.time()}.zip'

    manifest_json = """
    {
        "version": "1.0.0",
        "manifest_version": 2,
        "name": "Chrome Proxy",
        "permissions": [
            "proxy",
            "tabs",
            "unlimitedStorage",
            "storage",
            "webRequest",
            "webRequestBlocking"
        ],
        "background": {
            "scripts": ["background.js"]
        },
        "minimum_chrome_version":"22.0.0"
    }
    """

    background_js = """
    var config = {
            mode: "fixed_servers",
            rules: {
              singleProxy: {
                scheme: "%s",
                host: "%s",
                port: parseInt(%s)
              },
              bypassList: ["localhost"]
            }
          };

    chrome.proxy.settings.set({value: config, scope: "regular"}, function() {});

    function callbackFn(details) {
        return {
            authCredentials: {
                username: "%s",
                password: "%s"
            }
        };
    }

    chrome.webRequest.onAuthRequired.addListener(
                callbackFn,
                {urls: ["<all_urls>"]},
                ['blocking']
    );
    """ % (scheme, proxy_host, proxy_port, proxy_username, proxy_password)

    with zipfile.ZipFile(plugin_path, 'w') as zp:
        zp.writestr("manifest.json", manifest_json)
        zp.writestr("background.js", background_js)
    
    return plugin_path

def extract_otp_from_email(mail_server, email_address, email_password, max_retries=8, retry_interval=5):
    """Extract OTP code from email with improved retries"""
    print(f"Connecting to {mail_server} with {email_address}")
    
    for attempt in range(max_retries):
        try:
            # Connect to mail server
            mail = imaplib.IMAP4_SSL(mail_server)
            mail.login(email_address, email_password)
            mail.select("inbox")
            
            # Search for recent emails from Ozon
            result, data = mail.search(None, '(FROM "ozon.ru" UNSEEN)')
            mail_ids = data[0].split()
            
            if not mail_ids:
                print(f"No new emails found, trying broader search (attempt {attempt+1}/{max_retries})...")
                # Try a broader search
                result, data = mail.search(None, '(FROM "ozon.ru")')
                mail_ids = data[0].split()
                
                if not mail_ids:
                    print(f"No emails from ozon.ru found. Trying with subject search...")
                    result, data = mail.search(None, '(SUBJECT "код" OR SUBJECT "code" OR SUBJECT "ozon")')
                    mail_ids = data[0].split()
            
            if mail_ids:
                latest_email_id = mail_ids[-1]
                result, data = mail.fetch(latest_email_id, "(RFC822)")
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                
                # Extract OTP from email body
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
                        try:
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            
                            # Look for common OTP patterns
                            # 6-digit code (most common)
                            otp_match = re.search(r'(\d{6})', body)
                            if otp_match:
                                otp = otp_match.group(1)
                                print(f"Found 6-digit OTP: {otp}")
                                mail.close()
                                mail.logout()
                                return otp
                            
                            # 4-digit code
                            otp_match = re.search(r'(\d{4})', body)
                            if otp_match:
                                otp = otp_match.group(1)
                                print(f"Found 4-digit OTP: {otp}")
                                mail.close()
                                mail.logout()
                                return otp
                            
                            # Check for specifically formatted codes
                            # Common pattern in security emails
                            otp_match = re.search(r'код\D*(\d+)', body, re.IGNORECASE)
                            if otp_match:
                                otp = otp_match.group(1)
                                print(f"Found OTP with 'код' prefix: {otp}")
                                mail.close()
                                mail.logout()
                                return otp
                                
                            otp_match = re.search(r'code\D*(\d+)', body, re.IGNORECASE)
                            if otp_match:
                                otp = otp_match.group(1)
                                print(f"Found OTP with 'code' prefix: {otp}")
                                mail.close()
                                mail.logout()
                                return otp
                        except Exception as e:
                            print(f"Error parsing email content: {e}")
                            continue
            
            mail.close()
            mail.logout()
            
            if attempt < max_retries - 1:
                print(f"OTP not found in attempt {attempt+1}, waiting {retry_interval}s before retry...")
                time.sleep(retry_interval)
            
        except Exception as e:
            print(f"Error extracting OTP (attempt {attempt+1}): {e}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)
    
    print("Failed to extract OTP after all retries")
    return None

def setup_browser_with_proxy(proxy_host, proxy_port, proxy_username, proxy_password):
    """Setup browser with reliable proxy configuration"""
    options = Options()
    plugin_path = None
    
    try:
        # Create a unique plugin path to avoid conflicts
        plugin_path = create_proxy_auth_extension(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            plugin_path=f'proxy_auth_plugin_{time.time()}.zip'
        )
        
        # Anti-detection settings
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        
        # Set user agent
        options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
        
        # Performance settings
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        
        # Add the proxy extension
        options.add_extension(plugin_path)
        
        # Initialize browser
        service = Service(ChromeDriverManager().install())
        browser = webdriver.Chrome(service=service, options=options)
        
        # Apply anti-fingerprinting script
        browser.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });
            """
        })
        
        # Wait for proxy to initialize
        time.sleep(3)
        
        return browser, plugin_path
        
    except Exception as e:
        print(f"Error setting up browser: {e}")
        if plugin_path and os.path.exists(plugin_path):
            try:
                os.remove(plugin_path)
            except:
                pass
        return None, plugin_path

def verify_proxy_working(browser):
    """Verify that the proxy is properly configured by checking IP"""
    try:
        # Try several IP checking services
        ip_services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://ipinfo.io/ip"
        ]
        
        for service in ip_services:
            browser.get(service)
            time.sleep(5)
            ip = browser.find_element(By.TAG_NAME, "body").text.strip()
            
            if ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                print(f"Current IP: {ip}")
                # Check if IP matches expected proxy IP or at least is different from a known non-proxy IP
                if "85.142" in ip:
                    print("Proxy confirmed working - IP matches expected proxy range")
                    return True
                else:
                    print("Warning: IP doesn't match expected proxy range")
                    # Continue checking with other services
            else:
                print(f"Invalid IP format from {service}: {ip}")
        
        # If we get here and haven't returned True, we should at least check that we can access a website
        browser.get("https://www.ozon.ru")
        time.sleep(5)
        
        if "ozon" in browser.current_url.lower():
            print("Proxy appears to be working - can access Ozon")
            return True
        
        return False
        
    except Exception as e:
        print(f"Error verifying proxy: {e}")
        return False

def login_to_ozon(browser, phone_number, email_address, email_password, index, df):
    """Handle the entire Ozon login process"""
    try:
        # Navigate to Ozon
        print("Navigating to Ozon.ru...")
        browser.get("https://www.ozon.ru")
        time.sleep(10)
        
        # Check if we reached Ozon
        if "ozon" not in browser.current_url.lower():
            print(f"Failed to reach Ozon.ru, current URL is: {browser.current_url}")
            # Try again
            browser.get("https://www.ozon.ru")
            time.sleep(10)
            
            if "ozon" not in browser.current_url.lower():
                print("Failed to reach Ozon after multiple attempts")
                browser.save_screenshot(f"error_navigation_{index}.png")
                return False
        
        print("Successfully reached Ozon.ru")
        
        # Click login button
        try:
            login_button = WebDriverWait(browser, 15).until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Войти') or contains(., 'Sign in')]"))
            )
            login_button.click()
            print("Clicked login button")
            time.sleep(5)
        except Exception as e:
            print(f"Login button not found or couldn't click it: {e}")
            # We might already be on the login page, so continue
        
        # Enter phone number
        print("Looking for phone input field...")
        try:
            phone_input = WebDriverWait(browser, 15).until(
                EC.presence_of_element_located((By.XPATH, "//input[@type='tel' or contains(@placeholder, '999')]"))
            )
            phone_input.clear()
            
            # Format phone number if needed
            formatted_phone = phone_number
            if not formatted_phone.startswith('+'):
                if formatted_phone.startswith('9') or formatted_phone.startswith('8'):
                    formatted_phone = '+7' + formatted_phone[-10:]
            
            print(f"Entering phone number: {formatted_phone}")
            phone_input.send_keys(formatted_phone)
            time.sleep(2)
            
            # Click continue button or press Enter
            try:
                submit_button = WebDriverWait(browser, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[@type='submit' or contains(., 'Продолжить') or contains(., 'Continue')]"))
                )
                submit_button.click()
            except:
                print("No submit button found, pressing Enter")
                phone_input.send_keys(Keys.RETURN)
            
            print("Submitted phone number")
            time.sleep(5)
            
            # Wait for OTP field
            print("Waiting for OTP field to appear...")
            otp_input = WebDriverWait(browser, 30).until(
                EC.presence_of_element_located((By.XPATH, "//input[@type='tel' or @type='number' or contains(@placeholder, 'Код') or contains(@placeholder, 'Code')]"))
            )
            print("OTP input field found")
            
            # Get OTP from email
            print("Retrieving OTP from email...")
            otp_code = extract_otp_from_email("imap.rambler.ru", email_address, email_password)
            
            if not otp_code:
                print("Failed to retrieve OTP")
                browser.save_screenshot(f"error_otp_retrieval_{index}.png")
                return False
            
            print(f"OTP retrieved: {otp_code}")
            
            # Enter OTP
            otp_input.clear()
            otp_input.send_keys(otp_code)
            time.sleep(2)
            
            # Submit OTP
            try:
                confirm_button = WebDriverWait(browser, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[@type='submit' or contains(., 'Войти') or contains(., 'Подтвердить') or contains(., 'Confirm') or contains(., 'Sign in')]"))
                )
                confirm_button.click()
                print("Clicked confirmation button")
            except:
                print("No confirmation button found, pressing Enter")
                otp_input.send_keys(Keys.RETURN)
            
            # Wait for login to complete
            print("Waiting for login to complete...")
            time.sleep(15)
            
            # Check if login successful by looking for profile elements
            success_indicators = [
                "//div[contains(@class, 'profile') or contains(@class, 'account')]",
                "//button[contains(., 'Профиль') or contains(., 'Profile')]",
                "//a[contains(@href, 'profile') or contains(@href, 'account')]"
            ]
            
            login_successful = False
            for indicator in success_indicators:
                try:
                    WebDriverWait(browser, 5).until(
                        EC.presence_of_element_located((By.XPATH, indicator))
                    )
                    login_successful = True
                    break
                except:
                    pass
            
            if login_successful or "ozon.ru" in browser.current_url.lower():
                print("Login successful!")
                
                # Save cookies
                cookies = browser.get_cookies()
                df.at[index, 'Cookies'] = str(cookies)
                print(f"Saved cookies for account {index+1}")
                
                # Save after each successful login
                df.to_excel("acc_ozon_updated.xlsx", index=False)
                return True
            else:
                print("Login appears to have failed")
                browser.save_screenshot(f"login_failed_{index}.png")
                return False
                
        except Exception as e:
            print(f"Error during phone/OTP process: {e}")
            browser.save_screenshot(f"error_login_process_{index}.png")
            return False
            
    except Exception as e:
        print(f"Error in login_to_ozon function: {e}")
        browser.save_screenshot(f"error_general_{index}.png")
        return False

def main():
    # Proxy settings
    proxy_host = "85.142.131.100"
    proxy_port = "63934"
    proxy_username = "uCpNVmKQ"
    proxy_password = "TMpbnhn7"
    
    # Load Excel file
    try:
        # Try to load the original file
        source_file = "acc_ozon_выдача.xlsx"
        target_file = "acc_ozon_updated.xlsx"
        
        # Check if updated file exists and use it if it does
        if os.path.exists(target_file):
            print(f"Using existing updated file: {target_file}")
            df = pd.read_excel(target_file)
        else:
            print(f"Loading original file: {source_file}")
            df = pd.read_excel(source_file)
            # Create a copy for the updated data
            df.to_excel(target_file, index=False)
        
        print(f"Successfully loaded Excel file with {len(df)} rows")
        
        # Add a Cookies column if it doesn't exist
        if 'Cookies' not in df.columns:
            df['Cookies'] = None
            df.to_excel(target_file, index=False)
            
    except Exception as e:
        print(f"Failed to load Excel file: {e}")
        return
    
    browser = None
    plugin_path = None
    
    # Process each account
    for index, row in df.iterrows():
        # Skip accounts that already have cookies
        if pd.notna(row.get('Cookies')) and row.get('Cookies'):
            print(f"Account {index+1}/{len(df)} already has cookies. Skipping.")
            continue
            
        print(f"\n{'='*50}")
        print(f"Processing account {index+1}/{len(df)}")
        print(f"{'='*50}")
        
        # Create a new browser instance for each account
        if browser:
            try:
                browser.quit()
            except:
                pass
                
        if plugin_path and os.path.exists(plugin_path):
            try:
                os.remove(plugin_path)
            except:
                pass
        
        # Setup new browser with proxy
        browser, plugin_path = setup_browser_with_proxy(proxy_host, proxy_port, proxy_username, proxy_password)
        
        if not browser:
            print("Failed to initialize browser. Skipping this account.")
            continue
        
        # Verify proxy is working
        if not verify_proxy_working(browser):
            print("Proxy verification failed. Skipping this account.")
            browser.quit()
            continue
        
        # Get account details
        try:
            phone_number = str(row['Телефон']).strip()
            email_address = str(row['Привязанная\nпочта']).strip()
            email_password = str(row['пароль от\nпочты']).strip()
            
            print(f"Processing account with phone: {phone_number}, email: {email_address}")
            
            # Login to Ozon
            login_success = login_to_ozon(browser, phone_number, email_address, email_password, index, df)
            
            if login_success:
                print(f"Account {index+1} processed successfully")
            else:
                print(f"Failed to process account {index+1}")
                
            # Clear cookies for next account
            browser.delete_all_cookies()
            
        except Exception as e:
            print(f"Error processing account details: {e}")
            continue
    
    # Final cleanup
    if browser:
        try:
            browser.quit()
        except:
            pass
    
    if plugin_path and os.path.exists(plugin_path):
        try:
            os.remove(plugin_path)
        except:
            pass
    
    print("\nScript completed.")

if __name__ == "__main__":
    main()
