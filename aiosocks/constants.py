RSV = NULL = 0x00
SOCKS_VER4 = 0x04
SOCKS_VER5 = 0x05

SOCKS_CMD_CONNECT = 0x01
SOCKS_CMD_BIND = 0x02
SOCKS_CMD_UDP_ASSOCIATE = 0x03
SOCKS4_GRANTED = 0x5A
SOCKS5_GRANTED = 0x00

SOCKS5_AUTH_ANONYMOUS = 0x00
SOCKS5_AUTH_UNAME_PWD = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE_METHODS = 0xFF

SOCKS5_ATYP_IPv4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPv6 = 0x04

SOCKS4_ERRORS = {
    0x5B: 'Request rejected or failed',
    0x5C: 'Request rejected because SOCKS server '
          'cannot connect to identd on the client',
    0x5D: 'Request rejected because the client program '
          'and identd report different user-ids'
}

SOCKS5_ERRORS = {
    0x01: 'General SOCKS server failure',
    0x02: 'Connection not allowed by ruleset',
    0x03: 'Network unreachable',
    0x04: 'Host unreachable',
    0x05: 'Connection refused',
    0x06: 'TTL expired',
    0x07: 'Command not supported, or protocol error',
    0x08: 'Address type not supported'
}
