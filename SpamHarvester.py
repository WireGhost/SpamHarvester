##############################################################################
#                         #####                                              #  
#                        #    #  #####    ##    #    #                       # 
#                        #       #    #  #  #   ##  ##                       # 
#                        #####   #    #  #   #  # ## #                       # 
#                            #   #####  ######  # #  #                       # 
#                       #    #   #      #    #  #    #                       # 
#                       #####    #      #    #  #    #                       # 
#                                                                            # 
#      #     #                                                               # 
#      #     #   ##   #####  #    # ######  ####  ##### ###### #####         # 
#      #     #  #  #  #    # #    # #      #        #   #      #    #        # 
#      ####### #    # #    # #    # #####   ####    #   #####  #    #        # 
#      #     # ###### #####  #    # #           #   #   #      #####         # 
#      #     # #    # #   #   #  #  #      #    #   #   #      #   #         # 
#      #     # #    # #    #   ##   ######  ####    #   ###### #    #        #
#                                                                            #       
##############################################################################
                    # +-+-+-+-+ +-+-+ +-+-+ +-+-+-+#
                    # |B|e|t|a| |v|1| |B|y| |W|G|X|#
                    # +-+-+-+-+ +-+-+ +-+-+ +-+-+-+#
                    ################################                                                                                  
#Created By WireGhost  : 3.16.2023   
#The following Python Script is for harvesting data from Spam email headers:
#The relevant data collected from the headers is appended to a csv file: 
#From the csv file, elements, whether domain, URLs, IP, etc. Can be used to report or block. 
#Or it could be used for more interesting automated solutions. 
#Deployed as a scheduled task or cron job, it will automatically run and append to the csv. 
#This script is for personal email accounts. Prefferably an old account to use as a spam honeypot. 
#Created and Tested on Python 3.11.2 - Win 10 x64 

import imaplib
import email
import csv
import re
import socket
import whois

# Connect to the IMAP server and select the "Aphish" folder.
# You can rename "Aphish" to whatever subfolder name you choose. 
# Enter your email and enter your OTP below. 
imap = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
imap.login("YourEmail@yahoo.com","OneTimePass")
imap.select("Aphish")

# Searches for spam emails in the "Aphish" folder
search_criteria = "ALL"
status, messages = imap.search(None, search_criteria)

# Extracts the headers, body, subject, domains, IP's and URLs+ from each email and stores the results in a list. 
results = []
for message in messages[0].split():
    _, msg_data = imap.fetch(message, "(RFC822)")
    msg = email.message_from_string(msg_data[0][1].decode('utf-8', errors='ignore'))
    headers = msg.items()
    header_dict = {}
    for header in headers:
        header_dict[header[0].lower()] = header[1]
    body = msg.get_payload()
    if isinstance(body, list):
        # Check if the body is a list
        for part in body:
            if isinstance(part, email.message.Message):
                # If the part is a Message object, extract the payload
                body = part.get_payload()
                break
    urls = re.findall(r"\bhttps?://[^\s]+\b", body)
    results.append((header_dict, body, urls))

# Helper function to find "Received From" field from headers. 
def find_received_from(headers):
    received_from = []
    received_header = headers.get("received", "")
    received_fields = re.findall(r"from\s(.*?)(?=\swith|\n|$)", received_header, re.IGNORECASE)
    for field in received_fields:
        received_from.append(field.strip())
    return received_from

# Extracts the relevant information from the headers to append to csv. 
rows = []
for result, body, urls in results:
    row = {}
    received_from = find_received_from(result)
    row["Received From 1"] = received_from[0] if received_from else ""
    row["Received From 2"] = received_from[1] if len(received_from) > 1 else ""
    row["Received"] = result.get("received", "")
    row["From"] = result.get("from", "")
    row["Domain IP"] = ""
    row["Subject"] = result.get("subject", "")
    row["Delivered-To"] = result.get("delivered-to", "")
    row["X-Received"] = result.get("x-received", "")
    row["Return Path"] = result.get("return-path", "")
    row["Received-SPF"] = result.get("received-spf", "")
    row["Authentication Results"] = result.get("authentication-results", "")
    row["Reply-To"] = result.get("reply-to", "")
    row["Date"] = result.get("date", "")
    row["MIME Version"] = result.get("mime-version", "")
    row["Content Type"] = result.get("content-type", "")
    row["Content-Transfer-Encoding"] = result.get("content-transfer-encoding", "")
    row["Message ID"] = result.get("message-id", "")
    row["To"] = result.get("to", "")
    row["CC"] = result.get("cc", "")
    row["BCC"] = result.get("bcc", "")
    row["URLs"] = ", ".join(urls)

    if "received" in result:
        ip_address = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", result["received"])
        if ip_address:
            try:
                w = whois.whois(ip_address[0])
                row["Reporting Abuse Email"] = w.emails[0] if w.emails else "N/A"
                row["Domain IP"] = ip_address[0]
            except (socket.gaierror, whois.parser.PywhoisError, IndexError):
                row["Reporting Abuse Email"] = "N/A"

    rows.append(row)

# Writes the rows to a CSV file.
with open('addresses.csv', mode='w', newline='', encoding='utf-8') as file:
    fieldnames = [
        "Received From 1", "Received From 2", "Received", "From", "Domain IP", "Subject", "Delivered-To",
        "X-Received", "Return Path", "Received-SPF", "Authentication Results", "Reply-To", "Date",
        "MIME Version", "Content Type", "Content-Transfer-Encoding", "Message ID", "To", "CC", "BCC", "URLs",
        "Reporting Abuse Email"
    ]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    
# Marks all messages in the "Aphish" folder as read (can optionally delete). 
for message in messages[0].split():
    imap.store(message, "+FLAGS", "\\Seen")

# Closes the connection to the IMAP server. 
imap.close()
imap.logout()
# <FIN>

