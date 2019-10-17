# OAuth/OpenID Connect Workshop
This is a OpenID Connect example, used as an assigment in the OAuth2 and OpenID Connect workshop given by Curity AB.

## Dependencies

**python 3.7 (tested with python 3.7.4)

**OpenSSL 1.0** to be able to do modern TLS versions.


## Assignment

TODO!


## Running the app

```bash
$ pipenv shell
$ python app.py
```

Flask will start a web server listening on all interfaces. The webserver will by default use HTTPS with a selfsigned certificate for localhost.
Browse to https://localhost:5443 to see the app.

## settings.json
Settings.json is used as a configuration file for the example app. Change the values to match your system.

Name            | Type    | Mandatory | Default  | Description
----------------| ------- | :-------: | -------- | :---------------
`redirect_uri`  | string  |    ✓      |          | The redirect uri to use, must be registered for the client at the OpenID Connect server.
`client_id`     | string  |    ✓      |          | The id for the client. Used to authenticate the client.
`client_secret` | string  |    ✓      |          | The shared secret to use for authentication against the token endpoint.
`isser`         | URI     |    ✓      |          | The OAuth2 issuer
`scope`         | string  |           |          | The scopes to ask for.
`issuer`        | string  |    ✓      |          | The ID of the token issuer.
`verify_ssl_server` | boolean |       | `true`   | Set to false to disable certificate checks.
`debug`         | boolean |           | `false`  | If set to true, Flask will be in debug mode and write stacktraces if an error occurs
`port`          | number  |           | `9080`   | The port that the Flask server should listen to
`base_url`      | string  |           |          | base url to be added to internal redirects. Set this to enable the client to be behind a proxy.

## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io


Copyright (C) 2016 Curity AB.
