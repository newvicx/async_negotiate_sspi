# Async Negotiate SSPI
**Credit brandond for the [requests_negotiate_sspi](https://github.com/brandond/requests-negotiate-sspi) package which this package is built off.**

## Background
This package takes the base code from requests_negotiate_sppi and adapts it to work within the context of httpx auth flows. It supports HTTP(S) and Websocket connections and plugs into both the [httpx](https://www.python-httpx.org/) and [websockets](https://websockets.readthedocs.io/en/stable/) API's. In order to plug into these API's, async_negotiate_sspi requires 2 dependencies...
* [httpx_extensions](https://github.com/newvicx/httpx_extensions): An async client built on top of httpx. Without it, HTTP(S) requests authenticating through Kerberos or NTLM using this package will fail. Its API is identical to httpx and has been fully tested
* [ws_auth](https://github.com/newvicx/httpx_extensions): An extension of the WebsocketClientProtocol class for handling httpx-like auth flows. No additional setup is needed with this and you can use the websockets API as you normally would

## Installation
You can install async_negotiate_sspi via pip

    pip install async-negotiate-sspi

## Usage

### HTTP(S)

    import asyncio
	from httpx_extensions import ExClient
	from async_negotiate_sspi import NegotiateAuth
	
	async def main():
		auth = NegotiateAuth()
		with ExClient(auth=auth) as client:
			response = await client.get("https://iis.contoso.com")
	
	asyncio.run(main())

### Websockets

    import websockets
	import ws_auth	# required to pass auth parameter
	from async_negotiate_sspi import NegotiateAuthWS
	
	async def main():
		auth = NegotiateAuthWS()
		with websockets.connect("wss://iis.contoso.com", auth=auth) as client:
			data = await client.recv()
	
	asyncio.run(main())

## Options

 - service (str): Kerberos Service type for remote Service Principal Name - Default: "HTTP"
 - username (str): Username - Default: None
 - domain (str): NT Domain name - Default: "."
 - host (str): Host name for Service Principal Name - Default: Extracted from request URI
 - delegate (bool): Indicates that the user's credentials are to be delegated to the server - Default: False

## Supports
* Python >=3.7

## Requires
* httpx_extensions>=0.1.1
* ws_auth>=0.1.0
* pywin32>=303
	

