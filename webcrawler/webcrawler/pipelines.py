# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html

from scrapy import signals
from scrapy.exporters import CsvItemExporter
from __builtin__ import file

class WebcrawlerPipeline(object):
    def __init__ (self):
        self.files = {}
        pass
    
    @classmethod
    def from_crawler(cls, crawler):
        pipeline = cls()
        crawler.signals.connect(pipeline.spider_opened, signals.spider_opened)
        crawler.signals.connect(pipeline.spider_closed, signals.spider_closed)
        return pipeline
    
    def spider_opened(self, spider):
        file = open("%s_urls.txt" % (spider.name), "w+b")
        self.files[spider] = file
        self.exporter = CsvItemExporter(file, include_headers_line=False)
        self.exporter.start_exporting()
        pass
    
    def spider_closed(self, spider):
        self.exporter.finish_exporting()
        file = self.files.pop(spider)
        file.close()
        pass
    
    def process_item(self, item, spider):
        self.exporter.export_item(item)
        return item
    pass
