# Async Negotiate SSPI

**This is a port of brandond's [requests_negotiate_sspi](https://github.com/brandond/requests-negotiate-sspi) package. I want to make sure they get the appropriate credit. This package takes the base code from requests_negotiate_sppi and adapts it to work within the context of httpx auth flows. async_negotiate_sspi requires [httpx_extensions](https://github.com/newvicx/httpx_extensions) which is an async client built on top of httpx. httpx_extensions allows the user to control which connection requests are sent on in a pool. Without it, authentication through Kerberos and NTLM using this package will fail**

## Installation

You can install async_negotiate_auth via pip
	pip install async-negotiate-auth

## Usage

    import asyncio
	from httpx_extensions import ExClient
	from async_negotiate_sspi import NegotiateAuth
	
	async def main():
		auth = NegotiateAuth()
		with ExClient(auth=auth) as client:
			response = await client.get("https://iis.contoso.com")
	
	asyncio.run(main())

## Options

 - service (str): Kerberos Service type for remote Service Principal Name - Default: "HTTP"
 - username (str): Username - Default: None
 - domain (str): NT Domain name - Default: "."
 - host (str): Host name for Service Principal Name - Default: Extracted from request URI
 - delegate (bool): Indicates that the user's credentials are to be delegated to the server - Default: False

	

