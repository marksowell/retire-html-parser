import sys
import re
from bs4 import BeautifulSoup

def parse_file(file_path):
    try:
        with open(file_path, 'r') as file:
            contents = file.read()
    except FileNotFoundError:
        print(f"The file {file_path} does not exist.")
        sys.exit(1)

    soup = BeautifulSoup(contents, 'html.parser')

    # Find the table with id 'results'
    results_table = soup.find('table', {'id': 'results'})

    if not results_table:
        raise ValueError('No table with id "results" found')

    # Find all rows in the table with the class 'vulnerable'
    rows = results_table.find_all('tr', {'class': 'vulnerable'})

    if not rows:
        print("No vulnerable technologies found in the HTML file.")
        sys.exit(0)

    for row in rows:
        cells = row.find_all('td')

        if len(cells) < 3:
            continue

        # The first cell contains the library name
        library = cells[0].get_text(strip=True)

        # The second cell contains the library version
        version = cells[1].get_text(strip=True)

        # The third cell contains the location, but we need to exclude the vulnerability info
        location = cells[2].find(text=True, recursive=False).strip()

        # Use regular expression to find and replace underscores before "Vulnerability info:"
        location = re.sub(r'_+Vulnerability info:', '\nVulnerabilities:', location)

        print(f'\nLibrary: {library} (version: {version})')
        print(f'URL: {location}')

        # The vulnerability info is in a nested table
        vul_info_table = cells[2].find('table')
        vul_info_rows = vul_info_table.find_all('tr') if vul_info_table else []

        for info_row in vul_info_rows:
            severity = info_row.find_all('td')[0].get_text(strip=True).capitalize()
            description = info_row.find_all('td')[1].get_text(strip=True)
            print(f'{severity} - {description}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python retire_parser.py <filename>")
        sys.exit(1)

    file_path = sys.argv[1]
    parse_file(file_path)
