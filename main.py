import sys
import sqlite3
import requests
from lxml import html


class DBConnector:
    def __init__(self, db_path='./database.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.__init_tables()

    # Init tables they if not exists
    def __init_tables(self):
        cve_table = """
            create table if not exists `cve_table`(
            `lab_id` text not null,
            `name` TEXT NOT NULL,
            `cve_id` TEXT PRIMARY KEY,
            `cve_link` text not null,
            foreign key(`lab_id`) references `vulnerabilities`(`lab_id`)
            );
        """
        self.conn.execute(cve_table)

    def try_execute(self, sql):
        try:
            self.conn.execute(sql)
            self.conn.commit()
        except sqlite3.DatabaseError:
            # Pass if element already exists
            pass

    def db_insert_cve(self, cve_id, lab_id,  name, cve_link):
        sql = f"""
                INSERT INTO `cve_table`(`cve_id`, `lab_id`, `name`, `cve_link`) 
                VALUES ("{cve_id}", "{lab_id}", "{name}", "{cve_link}");
            """
        self.try_execute(sql)


class KasParser:
    def __init__(self):
        self.db = DBConnector()

    def __load_cve(self, kas_id, name):
        url = f'https://threats.kaspersky.com/en/vulnerability/{kas_id}/'
        req = requests.get(url)
        tree = html.fromstring(req.text)
        cve = tree.find_class('gtm_vulnerabilities_cve')

        for i in cve:
            self.db.db_insert_cve(i.text_content(), kas_id, name, i.get('href'))

    def __load_lab_id(self, product):
        product = product.replace(' ', '-')

        url = f'https://threats.kaspersky.com/en/product/{product}/'
        req = requests.get(url)
        if req.status_code == 404:
            # If cannot found the product
            raise RuntimeError('wrong name')

        tree = html.fromstring(req.text)

        lab_id = tree.find_class('gtm_vulnerabilities_lab_id')
        name = tree.find_class('gtm_vulnerabilities_name')

        for i in range(len(lab_id)):
            self.__load_cve(lab_id[i].text, name[i].text)

    def parse(self, name):
        self.__load_lab_id(name)


if __name__ == '__main__':
    product_name = ''
    if len(sys.argv) == 2:
        product_name = sys.argv[1]
    else:
        product_name = input()

    try:
        parser = KasParser()
        parser.parse(product_name)
        print('Completed. Check DB.')
    except RuntimeError as err:
        print(err)
