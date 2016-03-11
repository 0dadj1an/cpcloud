# -*- coding: utf-8 -*-

"""
cpcloud.exceptions
~~~~~~~~~~~~~~~~~~

This module contains the set of cpcloud exceptions.

"""

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class MissingCredentialsError(Error):
    """Exception raised when credentials are required but missing."""
    pass

class InvalidParameterError(Error):
    """Exception raised when a parameter value is deemed invalid."""
    pass

class DataNormalizationError(Error):
    """Exception raised when something bad happens during data normalization."""
    pass

class WebClientError(Error):
    """Exception raised when a web client runs into trouble."""
    def __init__(self, message, http_status_code=None):
        super(WebClientError, self).__init__(message)
        self.http_status_code = http_status_code

class AmazonClientError(WebClientError):
    """Exception raised when an Amazon web client runs into trouble."""
    pass

class AzureClientError(WebClientError):
    """Exception raised when an Azure web client runs into trouble."""
    pass

class GoogleClientError(WebClientError):
    """Exception raised when a Google web client runs into trouble."""
    pass

class CheckPointClientError(WebClientError):
    """Exception raised when a Check Point web client runs into trouble."""
    pass
