#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Logger, Utility for logging.
"""


import os


class Logger(object):

    def __init__(self, sequence, name):
        self.path = os.getcwd()
        self.sequence = sequence
        self.current_log = self.get_log_path(name)

    def get_log_path(self, log_name):
        path = os.path.join(self.path, ("{}_" + log_name).format(self.sequence))
        log = open(path, 'w')
        return log

    def log(self, msg):
        self.current_log.write(msg)

    def fin(self):
        self.current_log.flush()
        self.current_log.close()


class Singleton(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance


class LoggerFactory(Singleton, object):

    __sequence__ = 0

    def get_new_logger(self, log_name):
        self.__sequence__ += 1
        return Logger(self.__sequence__, log_name)
