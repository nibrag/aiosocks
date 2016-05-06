class SocksError(Exception):
    pass


class NoAcceptableAuthMethods(SocksError):
    pass


class LoginAuthenticationFailed(SocksError):
    pass


class InvalidServerVersion(SocksError):
    pass


class InvalidServerReply(SocksError):
    pass


class SocksConnectionError(OSError):
    pass
