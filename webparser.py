#!/usr/bnin/python3
# _*_ coding: utf-8 _*_
# Written by Casasura88

import socket
import sys
import logging
from urllib.parse import urljoin
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from html.parser import HTMLParser
from html.entities import name2codepoint
import re
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
import extruct


logging.basicConfig(
    format='%(asctime)s %(levelname)s:%(message)s',
    level=logging.INFO)
    

def process_domains(domains):
    for link in domains:
        link.url = url_query_cleaner(link.url)
        yield link


class MyHTMLParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        print("Start tag:", tag)
        for attr in attrs:
            print("     attr:", attr)

    def handle_endtag(self, tag):
        print("End tag  :", tag)

    def handle_data(self, data):
        print("Data     :", data)

    def handle_comment(self, data):
        print("Comment  :", data)

    def handle_entityref(self, name):
        c = chr(name2codepoint[name])
        print("Named ent:", c)

    def handle_charref(self, name):
        if name.startswith('x'):
            c = chr(int(name[1:], 16))
        else:
            c = chr(int(name))
        print("Num ent  :", c)

    def handle_decl(self, data):
        print("Decl     :", data)

parser = MyHTMLParser()

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print ("socket creation failed with error %s" %(err))
    
    port = 443, 80
 
try:
    host_ip = socket.gethostbyname('www.baykarsavunma.com')
except socket.gaierror:

    print ("there was an error resolving the host")
    sys.exit()
    
    s.connect((host_ip, port))
    print ("the socket has successfully connected to host")
    

class Extractor(CrawlSpider):
    
    def domains(self, domains=[]):
        self.allowed_domains = []
        self.domains_to_allow = domain
    
    def domainparser(Rule, domains):    
    	name = 'garantibbva'
    	allowed_domains = 'www.baykarsavunma.com/'
    	start_domains = 'http://www.baykarsavunma.com/'
    	rules = (
        	Rule(
        	    LinkExtractor(
        	        deny=[
        	            re.escape('http://www.baykarsavunma.com/offsite'),
        	            re.escape('http://www.baykarsavunma.com/whitelist'),
        	        ],
        	    ),
        	    process_links=process_links,
        	    callback='parse_item',
        	    follow=True
        	),
    	)

    def parse_item(self, response):
        return {
            'url': response.url,
            'metadata': extruct.extract(
                response.text,
                response.url,
                syntaxes=['opengraph', 'json-ld']
            ),
        }
    
    def extract_item(self, response):
        return {
            'url': response.url,
            'metadata': extruct.extract(
                response.text,
                response.url,
                syntaxes=['opengraph', 'json-ld']
            ),
        }


class Parser:

    def __init__(self, domains=[]):
        self.visited_domains = []
        self.domains_to_visit = domains
        
    def download_domain(self, domain):
        return requests.get(domain, verify=False).text

    def get_linked_domains(self, domain, html):
        soup = BeautifulSoup(html, 'html.parser')
        for link in soup.find_all('a'):
            path = link.get('href')
            if path and path.startswith('/'):
                path = urljoin(domain, path)
            yield path

    def parse_domain_to_visit(self, domain):
        if domain not in self.visited_domains and domain not in self.domains_to_visit:
            self.domains_to_visit.append(domain)

    def parse(self, domain):
        html = self.download_domain(domain)
        for domain in self.get_linked_domains(domain, html):
            self.parse_domain_to_visit(domain)
	    
    def run(self):
        while self.domains_to_visit:
            domain = self.domains_to_visit.pop(0)
            logging.info(f'Parsing: {domain}')
            try:
                self.parse(domain)
            except Exception:
                logging.exception(f'Failed to parse: {domain}')
            finally:
                self.visited_domains.append(domain)

if __name__ == '__main__':
    Parser(domains=['http://www.baykarsavunma.com/']).run()
    sys.exit()
