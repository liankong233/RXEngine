"""
headless-ida-mcp-server
"""
import os

from dotenv import find_dotenv, load_dotenv

from .logger import *

__all__ = ["PORT", "HOST", "TRANSPORT", "IDA_PATH"]

load_dotenv(find_dotenv(), override=True)
PORT = int(os.environ.get("PORT", 8888))
HOST = os.environ.get("HOST", "0.0.0.0")
TRANSPORT = os.environ.get("TRANSPORT", "sse")
IDA_PATH = os.environ.get("IDA_PATH", "")
if IDA_PATH == "":
    raise ValueError("IDA_PATH is not set")
