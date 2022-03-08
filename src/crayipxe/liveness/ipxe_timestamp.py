#
# MIT License
#
# (C) Copyright 2020-2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
'''
A set of routines for creating or reading from an existing timestamp file.
Created on April 2nd, 2020

@author: jason.sollom
'''
import datetime
import json
import logging
import os

LOGGER = logging.getLogger(__name__)
IPXE_PATH='/tmp/ipxe_build_in_progress'
DEBUG_IPXE_PATH='/tmp/debug_ipxe_build_in_progress'


class BaseipxeTimestampException(BaseException):
    pass


class ipxeTimestampNoEnt(BaseipxeTimestampException):
    """
    The Timestamp does not exist. 
    """
    pass


class ipxeTimestamp(object):

    def __init__(self, path, max_age, when=None):
        '''
        Creates a new timestamp representation to <path>; on initialization,
        this timestamp is written to disk in a persistent fashion.

        Newly initialized timestamps with a path reference to an existing file
        overwrites the file in question.
        
        Args:
        path (string): path to file containing the timestamp
        max_age (int): number of seconds before the timestamp is considered invalid 
        when (datetime Object): A datetime instance
        '''
        self.path = path
        try:
            os.makedirs(os.path.dirname(path))
        except FileExistsError:
            pass

        if not when:
            self.timestamp = datetime.datetime.now().timestamp()
        else:
            self.timestamp = when.timestamp()

        self.expiration = self.timestamp + float(max_age)

        with open(self.path, 'w') as timestamp_file:
            data = {'timestamp': self.timestamp,
                    'expiration': self.expiration}
            LOGGER.debug("Created timestamp file: %s "
                         "-- Timestamp: %s "
                         "Expiration: %s", path, data['timestamp'],
                         data['expiration'])
            json.dump(data, timestamp_file)
            

    @classmethod
    def byref(cls, path):
        """
        Creates a new instance of a Timestamp without initializing it to disk.
        This is useful if you simply want to check the existence of a timestamp
        without altering it.
        
        If the timestamp file does not exist, return None.
        
        Returns:
          A Timestamp object, if one exists
        
        Raises:
          ipxeTimestampNoEnt -- If path does not exist
        """
        if os.path.exists(path):
            self = cls.__new__(cls)
            self.path = path
            with open(self.path, 'r') as timestamp_file:
                data = json.load(timestamp_file)
                self.timestamp = float(data['timestamp'])
                self.expiration = float(data['expiration'])
                LOGGER.debug("Opened timestamp file: %s "
                             "-- Timestamp: %s "
                             "Expiration: %s", path, data['timestamp'],
                             data['expiration'])
            return self
        else:
            raise ipxeTimestampNoEnt

    @property
    def alive(self):
        """
        Has the time stamp expired?

        Return
          True -- The timestamp has not expired
          False -- The timestamp has expired
        """
        return datetime.datetime.now() < datetime.datetime.fromtimestamp(self.expiration)

    @property
    def value(self):
        """
        The timestamp value, as stored on disk. This property does not cache
        the value; instead it reads it each time the property is accessed.
        """
        try:
            with open(self.path, 'r') as timestamp_file:
                data = json.load(timestamp_file)
                return datetime.datetime.fromtimestamp(float(data['timestamp']))
        except FileNotFoundError:
            LOGGER.warning("Timestamp never intialized to '%s'" % (self.path))
            return datetime.datetime.fromtimestamp(0)

    def delete(self):
        """
        Delete the timestamp file
        """
        os.remove(self.path)