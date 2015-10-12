# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html


class WebcrawlerPipeline(object):
    def open_spider (self, spider):
        self.file = open("data.csv", "a")
        pass
    
    def close_spider (self, spider):
        self.file.close()
        pass
    
    def process_item(self, item, spider):
        self.file.write(item["content"])
        return item
    pass
