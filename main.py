import requests
from lxml import html
import sqlite3

db_path = "./database.db"

def create_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

if __name__ == "__main__":
    print("main")

    name = "KLA11641"
    url = f'https://threats.kaspersky.com/en/vulnerability/{name}/'

    r = requests.get(url)
    tree = html.fromstring(r.text)

    cve = tree.find_class('gtm_vulnerabilities_cve')

    for i in cve:
        print(i.get('href'))
        print(i.text_content())

    with open('test.html', 'w', encoding='utf-8') as output_file:
        output_file.write(r.text)
