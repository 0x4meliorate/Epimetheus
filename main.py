#!/usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import sys, os
import time

import xml.etree.ElementTree as ET
from progressbar import ProgressBar, Bar, ETA
from notifypy import Notify
import textwrap

from models import db
from models import CVE

def main(init):
    # Download latest XML data for CVE's.
    data = requests.get('https://cve.mitre.org/data/downloads/allitems-cvrf-year-2021.xml', stream=True)
    path = 'data/cves.xml'
    print("Downloading CVE's...")
    with open(path, 'wb') as f:
        total_length = int(data.headers.get('content-length'))
        download_bar = ProgressBar(widgets=[Bar('=', '[', ']'), ' ', ' ', ETA()], maxval=(total_length/1024) + 1).start() 
        for i, chunk in enumerate(data.iter_content(chunk_size=1024)):
            if chunk:
                download_bar.update(i)
                f.write(chunk)
                f.flush()

    # Parse XML data.
    tree = ET.parse('data/cves.xml')
    root = tree.getroot()
    # Find all vulnerabilities.
    vulns = root.findall('{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability')

    print("\nSyncing CVE's: "+str(len(vulns)))

    database_bar = ProgressBar(widgets=[Bar('=', '[', ']'), ' ', ' ', ETA()], maxval=len(vulns)).start()

    # For each vulnerability.
    for i, info in enumerate(vulns):
        database_bar.update(i)
        # Get the CVE title.
        title = info.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}CVE')
        # Create any array for each note/description.
        description = []
        # For each note in vulnerability.
        for note in info.findall('{http://www.icasi.org/CVRF/schema/vuln/1.1}Notes'):
            # Append each note to the final description.
            description.append(note.find('{http://www.icasi.org/CVRF/schema/vuln/1.1}Note').text)

        try:
            # Check if the CVE is disclosed.
            if "** RESERVED **" not in str(''.join(description)):
                # Does the CVE exist in the database
                cve_exists = CVE.query().filter(CVE.title == title.text).first()
                # If the CVE doesn't exist in the database.
                if cve_exists is None:
                    # If it's a database initialization, set the CVE to notified.
                    if init == True:
                        CVE.create(title=title.text, description=str(''.join(description)), notified=init).save()
                    # If it's not a database initialization, set the CVE to unnotified. 
                    else:
                        CVE.create(title=title.text, description=str(''.join(description)), notified=init).save()
        except Exception as e:
            print(e)
            pass

    # Pull CVE's that haven't been notified.
    cves = CVE.query().filter(CVE.notified == False)
    for cve in cves:
        # Notify user of newly disclosed CVE.
        notification = Notify()
        notification.title = cve.title
        notification.message = cve.description
        notification.icon = "data/icon.png"
        notification.send()

        cve.update(notified=True)
        # Sleep, so it doesn't send system notifications to fast.
        time.sleep(8)

    return

# help() - Print information on how to use Epimetheus.
def help():
    print("""
    ____ ___  _ _  _ ____ ___ _  _ ____ _  _ ____ 
    |___ |__] | |\/| |___  |  |__| |___ |  | [__  
    |___ |    | |  | |___  |  |  | |___ |__| ___] 
                                                
    In Greek mythology, Epimetheus (/ɛpɪˈmiːθiəs/; Greek: Ἐπιμηθεύς, which might mean "hindsight", literally "afterthinker")\n""")
    print("\tpython main.py initdb\n\t\tInitialize the database.")
    print("\tpython main.py scan\n\t\tScan and alert for new vulnerabilities.")
    print("\tpython main.py search chrome 15\n\t\tSearch for most recent CVE's.\n")

# If there is an argument.
if len(sys.argv) > 1:
    # Check if it's a database initialization.
    if sys.argv[1] == "initdb":
        print("Initializing database...\n")
        # Delete database.
        os.remove('data/vulns.db')
        # Recreate database.
        db.create_all()
        # Call main() with a parameter of init = True.
        main(True)

    # If the argument equals "scan".
    elif sys.argv[1] == "scan":
        # Setup infinite loop.
        while True:
            # Call main() with a parameter of init = False.
            main(False)
            # Sleep 60 seconds after scan.
            time.sleep(60)
            # Clear after scan.
            if os.name == 'nt':
                _ = os.system('cls')
            else:
                _ = os.system('clear')

    # If the argument equals "search".
    elif sys.argv[1] == "search" and len(sys.argv) > 3:
        keyword = '%' + str(sys.argv[2]) + '%' # Define keyword to find.
        limit = int(sys.argv[3])               # Define the amount of CVE's to find.
        # Pull CVE's.
        results = CVE.query().filter(CVE.description.like(keyword)).order_by(CVE.id.desc()).limit(limit).all()
        for cve in results:
            # Display CVE and description.
            print('\n\t' + cve.title + '\n\t\t' + textwrap.fill(cve.description, subsequent_indent='\t\t'))

    else:
        help()
else:
    help()
