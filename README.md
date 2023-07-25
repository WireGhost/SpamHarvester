# SpamHarvester
Basic Python script for having fun with python and spam emails.  
Title: Email Phishing Data Extractor – “Spam Harvester”

Summary:
The “SpamHarvester” is a simple Python script that helps users analyze and extract relevant information from phishing emails. It connects to an IMAP server, searches for spam emails in a specified folder ("Aphish"), and extracts headers, body text, and URLs from each email. The extracted data is then processed and saved to a CSV file for further analysis. For larger volumes of “spam processing”, it may be beneficial to append the output to SQLite DB. In this case, I had an old yahoo email account that was mostly spam and phishing, so I wanted to do something with it and have fun learning some Python header parsing.  With the Yahoo account, it didn’t connect with the default Yahoo “Spam” folder, so I made a subfolder called “Aphish” and passed the contents of the Spam folder to the “Aphish” subfolder.  Setting a filtering rule from the “Spam” folder to pass to “Aphish” didn’t work for me, as I was unable to select the Spam folder in Yahoo’s filtering rules, however; an email client i.e., Thunderbird may accomplish this.   

Features:

•	Connects securely to an IMAP server using IMAP4_SSL to access emails.
•	Extracts key email components, including sender, subject, date, and URLs.
•	Parses the email headers to identify the "Received From" fields.
•	Utilizes regular expressions to find URLs within the email body.
•	Performs a WHOIS lookup to determine the domain IP and reporting abuse email (if available).
•	Outputs the extracted data to a CSV file, easily importable into spreadsheet software.
•	Marks processed emails as "read" in the "Aphish" folder, preventing duplication in future runs.
Use Case:
The script is particularly useful for IT or InfoSec professionals, researchers, or anyone interested in analyzing phishing emails and identifying potential threats. By extracting and organizing relevant data, users can gain insights into the sources and patterns of phishing attempts. It can also serve as a foundation for further email analysis, machine learning projects, or building security awareness training datasets. Additionally, this script can be automated to run via Scheduled Task or Cron job, and will append the results to the csv output. 

Getting Started:

1.	Ensure Python is installed on your system (Python 3.x recommended).
2.	Update the script with your email credentials (server, login, and password).
3.	Customize the search folder, such as "Aphish," to match the target mailbox.
4.	Run the script to extract data from phishing emails.
5.	Review the generated CSV file for analysis, further processing, or sharing insights.
Note:
While the script is designed to be beginner-friendly, users with little Python experience can still learn valuable concepts related to email manipulation, regular expressions, and CSV file handling. It provides a practical foundation for exploring and advancing more complex email analysis and cybersecurity projects.

Feel free to modify and improve the script to suit your specific needs. I’m throwing it out here for folks to make it better and improve upon it. 
