#! /usr/bin/python
import json
from pprint import pprint

print "hello"

with open('data.json') as data_file:    
    data = json.load(data_file)

pprint(data)
