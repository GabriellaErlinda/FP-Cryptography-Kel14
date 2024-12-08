from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import random
import string
import time
from datetime import datetime, timedelta
from selenium.webdriver.chrome.options import Options

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_credit_card():
    return ''.join(random.choices(string.digits, k=16))

def generate_cvc():
    return ''.join(random.choices(string.digits, k=3))

def generate_expiry_date():
    current_date = datetime.now()
    future_date = current_date + timedelta(days=random.randint(1, 1825))
    return future_date.strftime("%m/%y")

def submit_form(driver, encryption_method):
    try:
        # Wait for form elements to be present
        wait = WebDriverWait(driver, 10)
        
        # Fill name field
        name_field = wait.until(EC.presence_of_element_located((By.NAME, "name")))
        name_field.clear()
        name_field.send_keys(generate_random_string(10))
        
        # Fill address field
        address_field = driver.find_element(By.NAME, "address")
        address_field.clear()
        address_field.send_keys(generate_random_string(20))
        
        # Fill credit card field
        cc_field = driver.find_element(By.NAME, "credit_card")
        cc_field.clear()
        cc_field.send_keys(generate_credit_card())
        
        # Fill expiry date field
        expiry_field = driver.find_element(By.NAME, "expiry_date")
        expiry_field.clear()
        expiry_field.send_keys(generate_expiry_date())
        
        # Fill CVC field
        cvc_field = driver.find_element(By.NAME, "cvc")
        cvc_field.clear()
        cvc_field.send_keys(generate_cvc())
        
        # Select encryption method
        encryption_select = Select(driver.find_element(By.NAME, "encryption_method"))
        encryption_select.select_by_value(encryption_method)
        
        # Submit form
        submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_button.click()
        
        time.sleep(1)  # Wait for submission to complete
        return True
        
    except Exception as e:
        print(f"Error during form submission: {str(e)}")
        return False

def main():
    # Set up Chrome options
    chrome_options = Options()
    # Uncomment the following line if you want to run in headless mode
    # chrome_options.add_argument('--headless')
    
    # Initialize the driver
    driver = webdriver.Chrome(options=chrome_options)
    base_url = "http://127.0.0.1:5000"
    num_submissions = 10  # Number of form submissions
    
    try:
        # Start with the checkout page
        driver.get(f"{base_url}/checkout")
        
        # Alternate between encryption methods
        encryption_methods = ['hybrid_chaotic']
        
        for i in range(num_submissions):
            current_method = encryption_methods[i % 2]
            
            # Submit the form
            success = submit_form(driver, current_method)
            
            if success:
                print(f"Successfully submitted form {i+1}/{num_submissions} using {current_method}")
            else:
                print(f"Failed to submit form {i+1}/{num_submissions}")
            
            # Go back to checkout page for next submission if not last submission
            if i < num_submissions - 1:
                driver.get(f"{base_url}/checkout")
            
            # Add a small delay between submissions
            time.sleep(2)
        
        # After all submissions, check the performance page
        print("\nChecking performance data...")
        driver.get(f"{base_url}/performance")
        time.sleep(2)  # Wait for performance page to load
        print("Performance page accessed successfully")
        
        # Keep the browser open to verify results
        input("\nPress Enter to close the browser...")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()