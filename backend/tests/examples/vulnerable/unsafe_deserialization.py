import pickle


def load_profile(data: bytes):
    return pickle.loads(data)
