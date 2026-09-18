# Matched Data CLI

Tool to interact with the Firewall matched data feature.

Additional documentation about the feature can be found on the [Cloudflare docs](https://developers.cloudflare.com/waf/managed-rulesets/payload-logging) and related [blog post](https://blog.cloudflare.com/using-hpke-to-encrypt-request-payloads/).

## Setup

`cargo build`

## Test

`cargo test`

## Usage

``` plain
USAGE:
    matched-data-cli <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt              Decrypts data
    generate-key-pair    Generates a public-private key pair
    help                 Prints this message or the help of the given subcommand(s)
```

To generate a key pair:

``` shell
$ matched-data-cli generate-key-pair
{
  "private_key": "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=",
  "public_key": "Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8="
}
```

To decrypt an encrypted matched data blob:

``` shell
$ cat private_key.txt
uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=
$ cat matched_data.txt
AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=
$ matched-data-cli decrypt -k private_key.txt matched_data.txt
test matched data
```

or using stdin, for example:

``` shell
$ cat private_key.txt
uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=
$ printf 'AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=' | matched-data-cli decrypt -k private_key.txt -
test matched data
```

To decrypt a list of firewall events, as exported from the Cloudflare dashboard, use the
`firewall-events-json` input format. Each event that has an `encrypted_matched_data` metadata
entry gets it replaced, in place, by a `matched_data` entry holding the decrypted payload; events
without one are passed through untouched:

``` shell
$ cat firewall-events.json
[
  {
    "ruleId": "6179ae15870a4bb7b2d480d4843b323c",
    "metadata": [
      {
        "key": "ruleset_version",
        "value": "87"
      },
      {
        "key": "encrypted_matched_data",
        "value": "AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk="
      }
    ]
  }
]
$ matched-data-cli decrypt -k private_key.txt -i firewall-events-json firewall-events.json
[
  {
    "ruleId": "6179ae15870a4bb7b2d480d4843b323c",
    "metadata": [
      {
        "key": "ruleset_version",
        "value": "87"
      },
      {
        "key": "matched_data",
        "value": "test matched data"
      }
    ]
  }
]
```

Events whose payload cannot be decrypted (for example, a payload that was truncated because it was
too large) are left as they are and reported on stderr, so a single failing event does not discard
the rest of the output.
