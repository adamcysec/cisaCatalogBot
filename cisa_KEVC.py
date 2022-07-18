import requests
from datetime import datetime

class catalog:
    def get_catalog(self):
        """web request to get the current CISA Known Exploited Vulnerabilities Catalog

        Returns:
        --------
        catalog_dict : dict
            the entire CISA vulnerability catalog
        """

        url = r'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        r = requests.get(url)
        catalog_dict = r.json()

        return catalog_dict
    
    def get_catalog_details(self):
        """get only the catalog metadata details

        Returns:
        --------
        catalog_dict : dict
            the CISA vulnerability catalog metadata
        """
        
        catalog_dict = self.get_catalog()
        catalog_dict.pop('vulnerabilities', None)

        return catalog_dict

    def get_catalog_by_date(self, date):
        """get all vulnerabilites added from a given date

        Parameters:
        -----------
        date : str
            mm/dd/yyyy time format
        date : datetime
            datetime object
        
        Returns:
        --------
        filter_catalog_dict : dict
            vulnerabilites that match the given filter
        """
        
        date_str = self.convert_datetime(date)
        catalog_dict = self.get_catalog()

        filter_catalog_dict = []
        for item in catalog_dict['vulnerabilities']:
            dateAdded = item['dateAdded']
            if dateAdded == date_str:
                filter_catalog_dict.append(item)
        
        return filter_catalog_dict

    def get_catalog_by_timeframe(self, start, end):
        """get all vulnerabiles within a given timeframe

        Parameters:
        -----------
        date : str
            mm/dd/yyyy time format
        date : datetime
            datetime object

        Returns:
        --------
        filter_catalog_dict : dict
            vulnerabilites that match the given filter
        """

        # convert timeframe into epoch timestamps
        start_date_epoch = datetime.strptime(self.convert_datetime(start), '%Y-%m-%d').timestamp()
        end_date_epoch = datetime.strptime(self.convert_datetime(end), '%Y-%m-%d').timestamp()
        
        catalog_dict = self.get_catalog()

        filter_catalog_dict = []
        for item in catalog_dict['vulnerabilities']:
            dateAdded = datetime.strptime(item['dateAdded'], '%Y-%m-%d').timestamp()

            if dateAdded >= start_date_epoch and dateAdded <= end_date_epoch:
                filter_catalog_dict.append(item)
            
        return filter_catalog_dict

    def get_top_vulnerabilites(self, num):
        """get the n most recent vulnerabilites

        Parameters:
        -----------
        num : int
            number of vulnerabiltes to return

        Returns:
        --------
        top_vulns : dict
            vulnerabiltes catalog
        """
        
        catalog_dict = self.get_catalog()

        top_vulns = catalog_dict['vulnerabilities'][-abs(num):]

        return top_vulns

    def convert_datetime(self, date):
        """convert user supplied date into the datetime format used by CISA

        Parameters:
        -----------
        date : str
            mm/dd/yyyy time format
        date : datetime
            datetime object

        Returns:
        --------
        date_str : str
            datetime format used by cisa (yyyy/mm/dd)
        """

        if str(type(date)) == "<class 'datetime.datetime'>":
            date_str = date.strftime('%Y-%m-%d')
        else:
            date_obj = datetime.strptime(date, '%m/%d/%Y')
            date_str = date_obj.strftime('%Y-%m-%d')

        return date_str