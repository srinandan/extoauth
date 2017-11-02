# extoauth
extoauth Apigee Edge Microgateway plugin allows Apigee Edge to integrate with external OAuth providers

## Support 
This is an open-source project of the Apigee Corporation. It is not covered by Apigee support contracts. However, we will support you as best we can. For help, please open an issue in this GitHub project. You are also always welcome to submit a pull request

## Install
```npm install extoauth```

## Enable
In the Microgateway configuration file, enable the plugin as follows:
```
  plugins:
    sequence:
	  - extoauth
      - oauth
```

NOTE: The extoauth plugin requires the oauth plugin and must appear in sequence before it.

## Configure
The plugin supports the following configuration parameters:
* `publickey_url`: Must point to an endpoint that returns an array of JWK, a PEM file or a list of PEM file (like OAuthv2 version1 Google Cloud)
* `client_id`: Specify where in the JWT the Aoigee API Key (aka Client ID) will be found. For example, Azure uses `azp`
* `exp`: Enable or disable checking expiry of the JWT token.
* `keyType`: This is set to `jwk` or `pem`. Default is `jwk`.

## How does it work?
The microgateway plugin validates the JWT, extracts the client_id claim and passes it to the API Key verification plugin (the OAuth plugin doubles as an API Key verification plugin also).