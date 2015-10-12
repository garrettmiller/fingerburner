import scrapy
from webcrawler.items import WebcrawlerItem
from scrapy.http import Request
from scrapy.selector import Selector
import re

def get_front_page (link):
    # Assuming that link fits the URL pattern, we will find the third
    # '/' and grab the substring before this. 
    # So: http://www.example.com/index.html will return 
    # http://www.example.com
    prot = link[:4].lower()
    if not prot == "http":
        return None
        
    count = 0
    index = 0
    for i in range(len(link)):
        if link[i] == '/':
            count += 1
            index = i
            if count == 3:
                break
            pass
        pass
        
    s = link[:index]
    return s
    
class WebSpider (scrapy.Spider):
    name = "webcrawler"
    start_urls = ["http://www.orbitz.com"]
    
    def __init__ (self, pattern=None, *args, **kwargs):
        super(WebSpider, self).__init__(*args, **kwargs)
        f = open(pattern, 'r')
        self.linkPattern = re.compile(f.read())
        f.close()
        self.crawledLinks = []
        pass
        
    def parse (self, response):
        links = response.selector.xpath("//a/@href").extract()
        
        for link in links:
            link = get_front_page(link)
            if not link:
                continue
            
            # If it is a proper link and is not checked yet, yield 
            # it to the Spider
            if self.linkPattern.match(link) and not link in self.crawledLinks:
                self.crawledLinks.append(link)
                yield Request (link, self.parse)
                
                item = WebcrawlerItem()
                item["url"] = link
                yield item
                pass
            pass
        pass

    pass
