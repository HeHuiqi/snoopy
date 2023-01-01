#! /usr/bin/env python
# -*- coding:utf-8 -*-
'''
@Author:Sunqh
@FileName: *.py
@Version:1.0.0
'''

import datetime
import inspect
import logging
import os
import sys


LOG_DIR = os.path.join(os.getcwd(), "logs")
if not os.path.exists(LOG_DIR):
    os.mkdir(LOG_DIR)
logfile = os.path.join(LOG_DIR, "run.log")

class Logger:
    def __init__(self):
        self._log_file = logfile
        self._logger = logging.getLogger("logger")
        self._logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(self._log_file)
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(hdlr=file_handler)
        if "--quiet" in sys.argv or "-q" in sys.argv:
            return
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(hdlr=stream_handler)
        self._logger.propagate = False

    def _format_message(self, level, message):
        """格式化将要输出日志信息

        :param level: str, 日志等级, INFO/WARN/ERROR/HIGHLIGHT
        :param message: str, 日志信息条目
        :return: str, 格式化的日志信息条目
        """
        frame = inspect.currentframe().f_back.f_back
        frame_info = inspect.getframeinfo(frame)
        line_no = frame_info.lineno
        file_name = frame_info.filename
        module_name = os.path.splitext(os.path.split(file_name)[1])[0]
        if module_name and line_no:
            message = "{time} - [{module}#{line}] - {level} - {message}".format(
                time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
                module=module_name, line=line_no, level=level, message=message)
        return message

    def set_level(self, level):
        if level == 'info':
            self._logger.setLevel(logging.INFO)
        elif level == 'debug':
            self._logger.setLevel(logging.DEBUG)

    def write_log_to_file(self, message):
        with open(logfile, "a", encoding="utf8") as tt:
            tt.write("[>>>>]  " + message + "\n")

    def info(self, message):
        self.write_log_to_file(self._format_message("INFO", message))
        self._logger.info(self._format_message("INFO", "{}[34;1m{}{}[0m".format(chr(27), message, chr(27))))

    def warn(self, message):
        self.write_log_to_file(self._format_message("WARN", message))
        self._logger.warning(self._format_message("WARN", "{}[33;1m{}{}[0m".format(chr(27), message, chr(27))))

    def error(self, message):
        self.write_log_to_file(self._format_message("ERROR", message))
        self._logger.error(self._format_message("ERROR", "{}[31;1m{}{}[0m".format(chr(27), message, chr(27))))

    def highlight(self, message):
        self.write_log_to_file(self._format_message("HIGHLIGHT", message))
        self._logger.critical(self._format_message("HIGHLIGHT", "{}[36;1m{}{}[0m".format(chr(27), message, chr(27))))

    def debug(self, message):
        self.write_log_to_file(self._format_message("DEBUG", message))
        self._logger.debug(self._format_message("DEBUG", "{}[31;1m{}{}[0m".format(chr(27), message, chr(27))))

    def exit(self, message):
        self.write_log_to_file(self._format_message("EXIT", message))
        self._logger.error(self._format_message("EXIT", "{}[35;1m{}{}[0m".format(chr(27), message, chr(27))))
        exit()


logger = Logger()
logger.set_level("info")
