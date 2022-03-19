import zlib
import codecs
import re

def decode_gzip(data):
    return zlib.decompress(data, 16 | zlib.MAX_WBITS)


def encode_url_utf8(data):
    hex_data = codecs.encode(data, 'hex')
    ret = ''
    for i, v in enumerate(hex_data):
        if i % 2 == 0:
            ret += r'%'
        ret += v
    return ret

def parse_hexdata(data : str):
    pure_data =  list( filter( lambda x: int(x , 16) >= 32 , data.split(":") ) )
    return "".join([ chr( int(i , 16) ) for i in pure_data ])