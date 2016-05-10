SOCKS proxy client for asyncio and aiohttp
==========================================
.. image:: https://travis-ci.org/nibrag/aiosocks.svg?branch=master
  :target: https://travis-ci.org/nibrag/aiosocks
  :align: right

.. image:: https://coveralls.io/repos/github/nibrag/aiosocks/badge.svg?branch=master
  :target: https://coveralls.io/github/nibrag/aiosocks?branch=master
  :align: right

.. image:: https://badge.fury.io/py/aiosocks.svg
  :target: https://badge.fury.io/py/aiosocks
  :align: right

Features
--------
- SOCKS4, SOCKS4a and SOCKS5 version
- SocksConnector for aiohttp
- SOCKS "CONNECT" command

TODO
----
- UDP associate
- TCP port binding

Usage
-----
direct usage
^^^^^^^^^^^^

.. code-block:: python

  import asyncio
  import aiosocks


  async def connect():
    socks5_addr = aiosocks.Socks5Addr('127.0.0.1', 1080)
    socks4_addr = aiosocks.Socks4Addr('127.0.0.1', 1080)
    
    socks5_auth = aiosocks.Socks5Auth('login', 'pwd')
    socks4_auth = aiosocks.Socks4Auth('ident')
  
    dst = ('github.com', 80)
    
    # socks5 connect
    transport, protocol = await aiosocks.create_connection(
        lambda: Protocol, proxy=socks5_addr, proxy_auth=socks5_auth, dst=dst)
    
    # socks4 connect
    transport, protocol = await aiosocks.create_connection(
        lambda: Protocol, proxy=socks4_addr, proxy_auth=socks4_auth, dst=dst)
        
    # socks4 without auth and local domain name resolving
    transport, protocol = await aiosocks.create_connection(
        lambda: Protocol, proxy=socks4_addr, proxy_auth=None, dst=dst, remote_resolve=False)

    # use socks protocol
    transport, protocol = await aiosocks.create_connection(
        None, proxy=socks4_addr, proxy_auth=None, dst=dst)
  
  
  if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(connect())
    loop.close()

error handling
^^^^^^^^^^^^^^

.. code-block:: python

    try:
      transport, protocol = await aiosocks.create_connection(
          lambda: Protocol, proxy=socks5_addr, proxy_auth=socks5_auth, dst=dst)
    except aiosocks.SocksConnectionError:
      # connection error
    except aiosocks.LoginAuthenticationFailed:
      # auth failed
    except aiosocks.NoAcceptableAuthMethods:
      # All offered SOCKS5 authentication methods were rejected
    except (aiosocks.InvalidServerVersion, aiosocks.InvalidServerReply):
      # something wrong
    except aiosocks.SocksError:
      # something other

aiohttp usage
^^^^^^^^^^^^^

.. code-block:: python

  import asyncio
  import aiohttp
  import aiosocks
  from aiosocks.connector import SocksConnector


  async def load_github_main():
    addr = aiosocks.Socks5Addr('127.0.0.1', 1080)
    auth = aiosocks.Socks5Auth('proxyuser1', password='pwd')

    # remote resolve
    # conn = SocksConnector(proxy=addr, proxy_auth=auth, remote_resolve=True)

    # or locale resolve
    conn = SocksConnector(proxy=addr, proxy_auth=auth, remote_resolve=False)

    try:
      with aiohttp.ClientSession(connector=conn) as ses:
        async with session.get('http://github.com/') as resp:
          if resp.status == 200:
            print(await resp.text())
    except aiohttp.ProxyConnectionError:
      # connection problem
    except aiosocks.SocksError:
      # communication problem
  
  
  if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(load_github_main())
    loop.close()
