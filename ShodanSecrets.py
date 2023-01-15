import shodan
import ssl
import tld
from tld import get_tld
from datetime import datetime
from datetime import timedelta
import re
from multiprocessing import Pool
import requests
from fake_useragent import UserAgent
import socket
import sys
print("python3 shodansecrets.py shodansearch")
SHODAN_API_KEY = "Bh6f5Oc7geYSPx9JQHnUGKsK06NZc5nH"
sensitive_data = ['password',
                  'secret',
                  'token',
                  'login',
                  'key',
                  'credentials',
                  'account',
                  'user',
                  'pw',
                  'pass',
                  'admin',
                  'access',
                  'credit',
                  'debit',
                  'social',
                  'security',
                  'identity',
                  'personal',
                  'financial',
                  'bank',
                  'confidential',
                  'private',
                  'sensitive',
                  'protected',
                  'secure',
                  'authentication',
                  'encryption',
                  'authorization',
                  'identity',
                  'login credentials'
                 ]

# Connect to the API
api = shodan.Shodan(SHODAN_API_KEY)

# Perform the search
results = api.search(sys.argv[1])

# Create a list of IPs
ips = [result['ip_str'] for result in results['matches']]

# Define the date range
start_date = datetime(2000, 1, 1)
end_date = datetime.now()

# Define the time delta
delta = timedelta(days=365)

# Collect https proxy list from a public source
proxies = []
response = requests.get('https://api.proxyscrape.com/?request=getproxies&proxytype=https&timeout=10000&country=all')
proxies = response.text.split('\n')

# Get random user agent
ua = UserAgent()

def get_domains(ip):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=ip)
        s.connect((ip, 443))
        cert = s.getpeercert()
        s.close()
        subject = dict(x[0] for x in cert['subject'])
        domain = subject['commonName']
        tld_domain = get_tld(domain)
        subdomains = [subdomain[0] for subdomain in cert['subjAltName']]
        return tld_domain, subdomains
    except Exception as e:
        print(f'Error: {e}')

def get_wayback_urls(domain):
    try:
        # Define the wayback url
        wayback_url = f'http://web.archive.org/cdx/search/cdx?url={domain}&output=json&from={start_date}&to={end_date}'
        # Send GET request to the wayback url
        response = requests.get(wayback_url)
        # Get the json response
        json_response = response.json()
        # Get all the urls from the json response
        urls = [url[2] for url in json_response]
        return urls
    except Exception as e:
        print(f'Error: {e}')

def grep_data(url):
    try:
        # Get random user agent and proxy
        headers = {'User-Agent': ua.random}
        proxy = random.choice(proxies)
        
        # Send GET request to the URL
        response = requests.get(url, headers=headers, proxies={'http': proxy, 'https': proxy})
        content = response.text
        # Iterate over the sensitive data
        for data in sensitive_data:
            # Use the `re` library to search the response text for sensitive data
            matches = re.findall(data, content)
            if matches:
                print(f'Sensitive data found: {data} at {url}')
    except Exception as e:
        print(f'Error: {e}')

def main():
    p = Pool(processes=10)
    domains_subdomains = p.map(get_domains, ips)
    p.terminate()
    p.join()
    domains = set(domains_subdomains)

    for domain_subdomain in domains_subdomains:
        try:
            domain, subdomains = domain_subdomains
            # Get all the available snapshots for the current domain
            urls = get_wayback_urls(domain)

            # Print the domain and the number of urls
            print(f'Domain: {domain} - URLs: {len(urls)}')

            # Iterate over the urls
            for url in urls:
                p = Pool(processes=10)
                p.map(grep_data, [url])
                p.terminate()
                p.join()
                
             # Iterate over the subdomains
            for subdomain in subdomains:
                subdomain_url = f'https://{subdomain}'
                subdomain_urls = get_wayback_urls(subdomain_url)
                print(f'Subdomain: {subdomain} - URLs: {len(subdomain_urls)}')
            # Iterate over the subdomain urls
                for subdomain_url in subdomain_urls:
                    p = Pool(processes=10)
                    p.map(grep_data, [subdomain_url])
                    p.terminate()
                    p.join()
        except Exception as e:
                print(f'Error: {e}')

if __name__ == '__main__':
    main()
