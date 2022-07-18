from cisa_KEVC import catalog
from datetime import datetime
import json
from twitterlib import twitterlib

def main():
    cisa = catalog()

    # you can send str date in mm/dd/yyyy
    # or a datetime object
    cisa_vulns = cisa.get_catalog_by_date(datetime.today())
    #cisa_vulns = cisa.get_catalog_by_date('07/12/2022')
    
    # read current db
    db_records = read_db()
    record_cves = []
    for item in db_records['records']:
        record_cves.append(item['cveID'])

    # compare cisa to db to find new vulns
    new_vulns = []
    for vuln in cisa_vulns:
        vuln_cve = vuln['cveID']
        if not vuln_cve in record_cves:
            new_vulns.append(vuln)

    if new_vulns:
        # tweet new vulns
        client = twitterlib()
        
        for record in new_vulns:
            tweet = format_tweet(record)
            response = client.create_tweet(tweet)

            # write new observed vulns to the database
            db_records['records'].append(record)

        db_message = write_db(db_records)
        print(db_message)
    else:
        print('no new vulnerabilites')

def format_tweet(cisa_vuln):
    """build tweet from cisa vuln

    Parameters:
    -----------
    cisa_vuln : dict
        cisa vuln record

    Returns:
    --------
    tweet : str
        tweet to sent to twitter
    """
    
    cve = cisa_vuln['cveID']
    vendor = cisa_vuln['vendorProject']
    product = cisa_vuln['product']

    vuln_name = cisa_vuln['vulnerabilityName']
    try:
        cve_link = cisa_vuln['notes']
    except:
        cve_link = f"https://nvd.nist.gov/vuln/detail/{cve}"
    # if blank
    if cve_link == '':
        cve_link = f"https://nvd.nist.gov/vuln/detail/{cve}"

    
    tweet = f"{cve}\n{vuln_name}\n{cve_link}\n#{vendor} #{product} #cisabot"
    
    return tweet

def read_db():
    """read all the database records

    Returns:
    --------
    db_dict : dict
        database records
    """
    
    with open('./db.txt', 'r') as f:
        db = f.read()
        db_dict = eval(db)

    return db_dict

def write_db(new_db_records):
    """write data to the database

    Parameters:
    -----------
    new_db_records : dict
        database records
    
    Returns:
    --------
    db_message : str
        message from database
    """
    
    with open('./db.txt', 'w') as f:
        json.dump(new_db_records, f)
    
    db_message = "db saved"
    return db_message

def reset_db():
    """reset the entire database

    Returns:
    --------
    db_message : str
        message from database
    """

    db = {}
    db['records'] = []
    with open('./db.txt', 'w') as f:
        json.dump(db, f)
    
    db_message = 'db reset'
    return db_message

if __name__ == "__main__":
    main()