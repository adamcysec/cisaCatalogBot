import tweepy
import requests
import os
import json

class twitterlib():
    def __init__(self):
        """handles authentication to twitter api
        """
        
        # read in authentication creds
        with open('./twitter_creds.txt','r') as f:
            creds = eval(f.read())
            self.consumer_key = creds["CONSUMER_KEY"]
            self.consumer_secret = creds["CONSUMER_SECRET"]
            self.bearer = creds["BEARER"]
            self.access_token = creds['ACCESSTOKEN']
            self.access_token_secret = creds['ACCESSTOKENSECRET']

        # authenticate to twitter
        self.api = tweepy.Client(bearer_token=self.bearer, consumer_key=self.consumer_key, consumer_secret=self.consumer_secret, access_token=self.access_token, access_token_secret=self.access_token_secret, wait_on_rate_limit=False)


    def create_tweet(self, tweet):
        """create tweet

        Parameters:
        -----------
        tweet : str
            the text to tweet

        Returns:
        --------
        response : requests
            reponse object from twiter
        """
        
        response = self.api.create_tweet(text=tweet)
        
        return response

