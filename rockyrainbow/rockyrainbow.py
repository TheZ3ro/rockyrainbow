#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from queue import Queue
from threading import Thread, Lock
import hashlib

# Numbers of concurrent threads
THREADS = 10

table = []

class HashConsumer(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue
        self.lock = Lock()

    def run(self):
        #with open("yolo",'w') as f:
            while True:
                word = self.queue.get()
                wordhash = hashlib.md5(word).hexdigest()
                word = word.decode()

                self.lock.acquire() # thread blocks at this line until it can obtain lock
                #f.write("{}:{}\n".format(word, wordhash))
                table.append("{}:{}\n".format(word, wordhash))
                #print("{}:{}".format(word, wordhash))
                self.lock.release()

                self.queue.task_done()


class RainbowScheduler(object):  # 🌈

    def __init__(self, wordlists, hash_function):
        self.wordlists = wordlists
        self.hash_function = hash_function

        # check if the hash_function is fine and supported

        self.queue = Queue()
        self.scheduling()

    def scheduling(self):
        # create workers
        for x in range(THREADS):
            worker = HashConsumer(self.queue)
            # Setting daemon to True will let the main thread exit
            # even though the workers are blocking
            worker.daemon = True
            worker.start()

        for wordlist in self.wordlists:
            PasswordProducer(wordlist, self.queue).crawl()


class PasswordProducer(object):

    def __init__(self, wordlist, queue):
        self.queue = queue
        self.wordlist = wordlist

    def crawl(self):
        with open(self.wordlist,'rb') as wlfile:
            lines = wlfile.readlines()

        for line in lines:
            self.queue.put(line.rstrip())

        # wait for the queue to finish processing all the tasks from one
        # single site
        self.queue.join()
        print("[%s] Finishing the rainbow" % self.wordlist)
        open("yolo",'w').write(''.join(table))
