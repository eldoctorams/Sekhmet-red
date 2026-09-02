import os
import pickle

API_KEY = "sk_test_1234567890abcdef"


def run(payload):
    os.system(payload)
    return pickle.loads(payload)
