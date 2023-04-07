from cisa_KEVC import catalog
from datetime import datetime
import json
from twitterlib import twitterlib
import argparse
import textwrap
import logging

def get_args():
    parser = argparse.ArgumentParser(
        description="Tweet every time Cisa updates their Known Exploited Vulnerabilites Catalog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Examples:
        python3 cisa_alerts.py
        python3 cisa_alerts.py --verbose
        python3 cisa_alerts.py --verbose --whatif
        python3 cisa_alerts.py -v --whatif
        ''')
    )

    parser.add_argument('--whatif', action='store_true', help="run this tool without prompting the user")
    parser.add_argument('--verbose', '-v', action='store_true', help="print verbose output")

    args = parser.parse_args() # parse arguments

    args_dict = vars(args)

    return args_dict

def main():
    args = get_args()
    whatif = args['whatif']
    verbose = args['verbose']
    cisa = catalog()

    # you can send str date in mm/dd/yyyy
    # or a datetime object
    cisa_vulns = cisa.get_catalog_by_date(datetime.today())
    #cisa_vulns = cisa.get_catalog_by_date('10/28/2022')
    py_logger.info(f"total vulns found: {len(cisa_vulns)}")

    
    # read current db
    db_records = read_db()
    record_cves = []
    for item in db_records['records']:
        record_cves.append(item['cveID'])
    if verbose:
        print("database read")
    

    # compare cisa to db to find new vulns
    new_vulns = []
    for vuln in cisa_vulns:
        vuln_cve = vuln['cveID']
        if not vuln_cve in record_cves:
            new_vulns.append(vuln)

    if new_vulns:
        py_logger.info(f"New vulns found: {len(new_vulns)}")
        if verbose:
            print("new vulnerabilites found")
        
        # tweet new vulns
        client = twitterlib()
        
        for record in new_vulns:
            tweet = format_tweet(record)
            if whatif:
                print("whatif prevented tweet...")
            else:
                py_logger.info(f"attempting to send vuln tweet name: {record['vulnerabilityName']} | {record['cveID']}")
                response = client.create_tweet(tweet)
                py_logger.info(f"tweet response code: {response.status_code}")
                
                
            if verbose:
                print("tweet sent")

            # write new observed vulns to the database
            db_records['records'].append(record)

        if whatif:
            print("whatif prevented database write...")
            db_message = ""
        else:
            db_message = write_db(db_records)
        
        if verbose:
            print("saved vulnerabilites to database")
        
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
    # get a custom logger & set the logging level
    py_logger = logging.getLogger(__name__)
    py_logger.setLevel(logging.INFO)

    # configure the handler and formatter as needed
    py_handler = logging.FileHandler("cisa_alerts'.log", mode='w')
    py_formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

    # add formatter to the handler
    py_handler.setFormatter(py_formatter)
    
    # add handler to the logger
    py_logger.addHandler(py_handler)

    main()