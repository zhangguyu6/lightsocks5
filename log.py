#-*- coding: utf-8 -*-
import logging
log=logging.getLogger("test")
log.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
log.addHandler(ch)
