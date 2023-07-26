# Retire HTML Parser

Retire HTML Parser is a Python script that parses an HTML file containing information about vulnerable technologies and displays the details in a human-readable format.

## Table of Contents

- [Introduction](#introduction)
- [Usage](#usage)
- [Requirements](#requirements)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Sample Output](#sample-output)
- [License](#license)

## Introduction

Retire HTML Parser is designed to parse HTML files generated by the [Retire.js](https://github.com/RetireJS/retire.js) tool. Retire.js is a tool that helps detect vulnerable JavaScript libraries in web applications.

This script extracts information about vulnerable technologies, including their library name, version, URL, and associated vulnerabilities. It then presents this information in a more readable format, making it easier for developers and security professionals to review and address potential security issues.

## Usage

The script takes a single command-line argument, which is the path to the HTML file containing the Retire.js scan results. It will then display the parsed information about the vulnerable technologies and their associated vulnerabilities.

## Requirements

- Python 3.x
- BeautifulSoup 4 (bs4)

## Installation

1. Ensure you have Python 3.x installed on your system.
2. Install the required dependencies using pip:

```bash
pip install beautifulsoup4
```

## How to Run

1. Clone or download this repository to your local machine.
2. Open a terminal or command prompt and navigate to the directory where you saved the script.
3. Save the report:
![Save report](images/save_report.png)
5. Run the script using the following command:

```bash
python retire_parser.py <filename>
```

Replace <filename> with the path to the HTML file containing the Retire.js scan results.

## Sample Output

Here is an example of how the output of the script will look:

```text
Library: jquery-ui (version: 1.12.1)
URL: Found in https://code.jquery.com/ui/1.12.1/jquery-ui.min.js
Vulnerabilities:
Medium - XSS when refreshing checkboxes if user-controlled data in labels 2101 CVE-2022-31160 GHSA-h6gj-6jjq-h8g9
Medium - CVE-2021-41184 XSS in the `of` option of the `.position()` util GHSA-gpqq-952q-5327
Medium - CVE-2021-41183 15284 XSS Vulnerability on text options of jQuery UI datepicker GHSA-j7qv-pgf6-hvh4
Medium - CVE-2021-41182 XSS in the `altField` option of the Datepicker widget GHSA-9gj3-hwp5-pmwc
Medium - CVE-2022-31160 XSS when refreshing a checkboxradio with an HTML-like initial text label GHSA-h6gj-6jjq-h8g9

Library: jquery (version: 3.4.1.min)
URL: Found in https://code.jquery.com/jquery-3.4.1.min.js
Vulnerabilities:
Medium - CVE-2020-11022 4642 Regex in its jQuery.htmlPrefilter sometimes may introduce XSS GHSA-gxr4-xjj5-5px2
Medium - CVE-2020-11023 CVE-2020-23064 4647 passing HTML containing <option> elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code GHSA-jpcq-cgw6-v4j6
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
