# Managing Documentation

## Initial setup

1. You must install [mkdocs](https://www.mkdocs.org) `brew install mkdocs`
1. Install the [material theme](https://squidfunk.github.io/mkdocs-material/): `pip install mkdocs-material`

## Testing

Run the mkdocs server on localhost:8000: `make serve-docs`

## Deploy

We utilize a github action to automatically update [the docs](https://synfinatic.github.io/aws-sso-cli/).

## Future

Really should run the service via docker... would be easy enough!
