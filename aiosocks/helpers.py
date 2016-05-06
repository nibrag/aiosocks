from collections import namedtuple

__all__ = ('Socks4Auth', 'Socks5Auth', 'Socks4Server', 'Socks5Server', 'SocksServer')


class Socks4Auth(namedtuple('Socks4Auth', ['login', 'encoding'])):
    def __new__(cls, login, encoding='utf-8'):
        if login is None:
            raise ValueError('None is not allowed as login value')

        return super().__new__(cls, login.encode(encoding), encoding)


class Socks5Auth(namedtuple('Socks5Auth', ['login', 'password', 'encoding'])):
    def __new__(cls, login, password, encoding='utf-8'):
        if login is None:
            raise ValueError('None is not allowed as login value')

        if password is None:
            raise ValueError('None is not allowed as password value')

        return super().__new__(cls,
                               login.encode(encoding),
                               password.encode(encoding), encoding)


class SocksServer(namedtuple('SocksServer', ['host', 'port'])):
    def __new__(cls, host, port):
        if host is None:
            raise ValueError('None is not allowed as host value')

        if port is None:
            port = 1080  # default socks server port

        return super().__new__(cls, host, port)


class Socks4Server(SocksServer):
    pass


class Socks5Server(SocksServer):
    pass
