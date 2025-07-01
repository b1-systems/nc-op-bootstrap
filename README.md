This is a--yet to be completed--rewrite of the original bash script found
[here](https://github.com/nextcloud/integration_openproject/blob/c4295155d162966cfd42bdcee0e9b59762c6bf2b/integration_setup.sh)

**NOTE:** Just a couple days after we wrote this script, a newer version of the
integration with external OIDC support was released. This new feature was not part of the
rewrite.

### TODOs

- [ ] Also use ENV vars in addition to `config.cnf`
- [ ] Better retry mechanism
- [ ] Use max retries config option
- [ ] Retry whenever sensible
