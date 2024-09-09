import requests
from bs4 import BeautifulSoup
from urllib import *
from urllib.parse import urljoin
from pyfiglet import Figlet


var_url= set()

def spider_url(url):
    try:
        res = requests.get(url)
        print(res)
    except:
        print("Request failed",url)
        return
    if (res.status_code == 200):
        soup = BeautifulSoup(res.content,'html.parser')
        # hi = []
        # hi = soup
        # with open ("outputww.txt",'w') as file:
        #     for i in hi:
        #         file.write(soup)
        print(soup)
            
    a_tag = soup.find_all('a')  # To find the all a tag 
    empty_list =[]
    for i in a_tag:
        her = i.get("href")
        if her is not None and her != "":   # if a tag has some value of lnk
            empty_list.append(her)
    with open ("output.txt",'w') as file:
        for i in empty_list:
            file.write(i+"\n")

#    #delete same url
#     for url1 in empty_list:
#         if url1 not in var_url:
#             var_url.add(url1)
#             url_join = urljoin(url, url1) #bug
#             if key in url_join:
#                 print(url_join)
#                 spider_url(url_join,key)
#         else:
#             pass


custom_fig = Figlet(font='graffiti') #graffiti , big
print(custom_fig.renderText('InfoGrabber!!'))
url = 'https://www.yahoo.com' #input("Enter the URL to search :")
# key = 'yahoo' #input("Enter a key to search in url :")
spider_url(url)

# https://www.yahoo.com --------- target web
