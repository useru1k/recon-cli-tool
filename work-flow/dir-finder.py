import requests
import os

url = input()
res = requests.get(url)
print(res)
