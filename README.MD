# Carbon Black - ReversingLabs TiScale Connector

The ReversingLabs TiScale connector submits binaries collected by Carbon Black to ReversingLabs
for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black server. The feed will then tag any binaries executed on your
endpoints identified as malware by ReversingLabs. Only binaries submitted by the TiScale connector
for analysis will be included in the generated Intelligence Feed.

**To use the TiScale connector, you must have a ReversingLabs TiScale Private API key.** You can
apply for a private API key through the ReversingLabs web interface. ReversingLabs Private API keys
are only available via a paid subscription to ReversingLabs.

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-reversinglabs-tiscale-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/reversinglabs-tiscale/connector.conf.example` file to
`/etc/cb/integrations/reversinglabs-tiscale/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for ReversingLabs into the configuration file: place base url (eg. https://192.168.1.1/)
into `reversinglabs_tiscale_host` and API token into the `tiscale_api_token` variables in the `/etc/cb/integrations/reversinglabs-tiscale/connector.conf` file.

Any errors will be logged into `/var/log/cb/integrations/reversinglabs-tiscale/reversinglabs.log`.

## Additional Configuration Options

## Troubleshooting

If you suspect a problem, please first look at the ReversingLabs TiScale connector logs found here:
`/var/log/cb/integrations/reversinglabs-tiscale/reversinglabs.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-reversinglabs-tiscale-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/reversinglabs-tiscale/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-reversinglabs-tiscale-connector start`

## Contacting Carbon Black Developer Relations Support

Web: https://community.carbonblack.com/groups/developer-relations
E-mail: dev-support@bcarbonblack.com

### Reporting Problems

When you contact Carbon Black Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM)
* For documentation issues, specify the version of the manual you are using.
* Action causing the problem, error message returned, and event log output (as appropriate)
* Problem severity

