import scrapy
from webcrawler.items import WebcrawlerItem
from scrapy.http import Request
from scrapy.selector import Selector
import re

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
        hxs = Selector(response)
        links = hxs.select("//a/@href").extract()
        
        for link in links:
            # If it is a proper link and is not checked yet, yield 
            # it to the Spider
            if self.linkPattern.match(link) and not link in self.crawledLinks:
                self.crawledLinks.append(link)
                yield Request (link, self.parse)
                pass
            pass
        
        item = WebcrawlerItem()
        item["content"] = response.body
        yield item
        
        pass

    pass
