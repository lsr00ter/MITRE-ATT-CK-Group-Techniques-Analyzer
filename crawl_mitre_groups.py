import requests
from bs4 import BeautifulSoup
import pandas as pd

# URL of the MITRE ATT&CK Groups page
groups_url = "https://attack.mitre.org/groups/"

# Fetch the page
response = requests.get(groups_url)
soup = BeautifulSoup(response.text, 'html.parser')

table = soup.find('table')
headers = [th.text.strip() for th in table.find('tr').find_all('th')]
rows = []
for tr in table.find_all('tr')[1:]:
    cols = [td.text.strip() for td in tr.find_all('td')]
    if cols:
        rows.append(cols)

df = pd.DataFrame(rows, columns=headers)
df.to_csv('mitre_attack_groups.csv', index=False)
print('Saved mitre_attack_groups.csv')
