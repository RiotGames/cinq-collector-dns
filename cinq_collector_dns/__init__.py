import requests
from cloud_inquisitor.config import dbconfig, ConfigOption
from cloud_inquisitor.constants import AccountTypes
from cloud_inquisitor.database import db
from cloud_inquisitor.exceptions import CloudFlareError
from cloud_inquisitor.plugins import BaseCollector, CollectorType
from cloud_inquisitor.plugins.types.resources import DNSZone, DNSRecord
from cloud_inquisitor.schema import Account
from cloud_inquisitor.utils import get_resource_id
from cloud_inquisitor.wrappers import retry
from dns import zone as dns_zone, query
from dns.rdatatype import to_text as type_to_text

AXFR_ACCOUNT_NAME = 'DNS: AXFR'
CF_ACCOUNT_NAME = 'DNS: CloudFlare'

class DNSCollector(BaseCollector):
    name = 'DNS'
    ns = 'collector_dns'
    type = CollectorType.GLOBAL
    interval = dbconfig.get('interval', ns, 15)
    options = (
        ConfigOption('enabled', False, 'bool', 'Enable the DNS collector plugin'),
        ConfigOption('interval', 15, 'int', 'Run frequency in minutes'),
        ConfigOption('cloudflare_api_key', '', 'string', 'CloudFlare API Key'),
        ConfigOption('cloudflare_email', '', 'string', 'Email address associated with the API key'),
        ConfigOption('cloudflare_enabled', False, 'bool', 'Enable CloudFlare as a source for DNS records'),
        ConfigOption('cloudflare_endpoint', 'https://api.cloudflare.com/client/v4', 'string',
                     'CloudFlare API endpoint'),
        ConfigOption('axfr_domains', [], 'array', 'Domains to attempt to perform zone transfers for'),
        ConfigOption('axfr_server', '', 'string', 'Server from where to request zone transfers'),
        ConfigOption('axfr_enabled', False, 'bool', 'Enable using DNS Zone Transfers for records')
    )

    def __init__(self):
        super().__init__()

        self.axfr_enabled = self.dbconfig.get('axfr_enabled', self.ns, False)
        self.axfr_server = self.dbconfig.get('axfr_server', self.ns)
        self.axfr_domains = self.dbconfig.get('axfr_domains', self.ns)

        self.cloudflare_enabled = self.dbconfig.get('cloudflare_enabled', self.ns, False)
        self.cloudflare_api_key = self.dbconfig.get('cloudflare_api_key', self.ns)
        self.cloudflare_email = self.dbconfig.get('cloudflare_email', self.ns)
        self.cloudflare_endpoint = self.dbconfig.get('cloudflare_endpoint', self.ns)
        self.cloudflare_initialized = False
        self.cloudflare_session = None

        if self.axfr_enabled:
            acct = Account.get(AXFR_ACCOUNT_NAME)
            if not acct:
                acct = Account()
                acct.account_name = AXFR_ACCOUNT_NAME
                acct.account_number = sum(map(ord, AXFR_ACCOUNT_NAME)) * -1
                acct.account_type = AccountTypes.DNS_AXFR
                acct.contacts = []
                acct.enabled = True

                db.session.add(acct)
                db.session.commit()

            self.axfr_account = acct

        if self.cloudflare_enabled:
            acct = Account.get(CF_ACCOUNT_NAME)
            if not acct:
                acct = Account()
                acct.account_name = CF_ACCOUNT_NAME
                acct.account_number = sum(map(ord, CF_ACCOUNT_NAME)) * -1
                acct.account_type = AccountTypes.DNS_CLOUDFLARE
                acct.contacts = []
                acct.enabled = True

                db.session.add(acct)
                db.session.commit()

            self.cloudflare_account = acct

    def run(self):
        if self.axfr_enabled:
            try:
                self.process_zones(self.get_axfr_records(), self.axfr_account)
            except:
                self.log.exception('Failed processing domains via AXFR')

        if self.cloudflare_enabled:
            try:
                self.process_zones(self.get_cloudflare_records(), self.cloudflare_account)
            except:
                self.log.exception('Failed processing domains via CloudFlare')

    def process_zones(self, zones, account):
        self.log.info('Processing DNS records for {}'.format(account.account_name))

        # region Update zones
        existing_zones = DNSZone.get_all(account)
        for data in zones:
            if data['zone_id'] in existing_zones:
                zone = DNSZone.get(data['zone_id'])
                if zone.update(data):
                    self.log.debug('Change detected for DNS zone {}/{}'.format(
                        account.account_name,
                        zone.name
                    ))
                    db.session.add(zone.resource)
            else:
                DNSZone.create(
                    data['zone_id'],
                    account_id=account.account_id,
                    properties={k: v for k, v in data.items() if k not in ('records', 'zone_id', 'tags')},
                    tags=data['tags']
                )

                self.log.debug('Added DNS zone {}/{}'.format(
                    account.account_name,
                    data['name']
                ))

        db.session.commit()

        zk = set(x['zone_id'] for x in zones)
        ezk = set(existing_zones.keys())

        for resource_id in ezk - zk:
            zone = existing_zones[resource_id]

            # Delete all the records for the zone
            for record in zone.records:
                db.session.delete(record.resource)

            db.session.delete(zone.resource)
            self.log.debug('Deleted DNS zone {}/{}'.format(
                account.account_name,
                zone.name.value
            ))
        db.session.commit()
        # endregion

        # region Update resource records
        for zone in zones:
            try:
                existing_zone = DNSZone.get(zone['zone_id'])
                existing_records = {rec.id: rec for rec in existing_zone.records}

                for data in zone['records']:
                    if data['id'] in existing_records:
                        record = existing_records[data['id']]
                        if record.update(data):
                            self.log.debug('Changed detected for DNSRecord {}/{}/{}'.format(
                                account.account_name,
                                zone.name,
                                data['name']
                            ))
                            db.session.add(record.resource)
                    else:
                        record = DNSRecord.create(
                            data['id'],
                            account_id=account.account_id,
                            properties={k: v for k, v in data.items() if k not in ('records', 'zone_id')},
                            tags={}
                        )
                        self.log.debug('Added new DNSRecord {}/{}/{}'.format(
                            account.account_name,
                            zone['name'],
                            data['name']
                        ))
                        existing_zone.add_record(record)
                db.session.commit()

                rk = set(x['id'] for x in zone['records'])
                erk = set(existing_records.keys())

                for resource_id in erk - rk:
                    record = existing_records[resource_id]
                    db.session.delete(record.resource)
                    self.log.debug('Deleted DNSRecord {}/{}/{}'.format(
                        account.account_name,
                        zone['zone_id'],
                        record.name
                    ))
                db.session.commit()
            except:
                self.log.exception('Error while attempting to update records for {}/{}'.format(
                    account.account_name,
                    zone['zone_id'],
                ))
                db.session.rollback()
        # endregion

    @retry
    def get_axfr_records(self):
        """Return a `list` of `dict`s containing the zones and their records, obtained from the DNS server

        Returns:
            :obj:`list` of `dict`
        """
        zones = []
        for zoneName in self.axfr_domains:
            try:
                zone = {
                    'zone_id': get_resource_id('axfrz', zoneName),
                    'name': zoneName,
                    'source': 'AXFR',
                    'comment': None,
                    'tags': {},
                    'records': []
                }

                z = dns_zone.from_xfr(query.xfr(self.axfr_server, zoneName))
                rdata_fields = ('name', 'ttl', 'rdata')
                for rr in [dict(zip(rdata_fields, x)) for x in z.iterate_rdatas()]:
                    record_name = rr['name'].derelativize(z.origin).to_text()
                    zone['records'].append(
                    {
                        'id': get_resource_id('axfrr', record_name, ['{}={}'.format(k, str(v)) for k, v in rr.items()]),
                        'zone_id': zone['zone_id'],
                        'name': record_name,
                        'value': sorted([rr['rdata'].to_text()]),
                        'type': type_to_text(rr['rdata'].rdtype)
                    })

                if len(zone['records']) > 0:
                    zones.append(zone)

            except Exception as ex:
                self.log.exception('Failed fetching DNS zone information for {}: {}'.format(zoneName, ex))
                raise

        return zones

    def get_cloudflare_records(self):
        """Return a `list` of `dict`s containing the zones and their records, obtained from the CloudFlare API

        Returns:
            :obj:`list` of `dict`
        """
        zones = []

        for zobj in self.__cloudflare_list_zones():
            try:
                self.log.debug('Processing DNS zone CloudFlare/{}'.format(zobj['name']))
                zone = {
                    'zone_id': get_resource_id('cfz', zobj['name']),
                    'name': zobj['name'],
                    'source': 'CloudFlare',
                    'comment': None,
                    'tags': {},
                    'records': []
                }

                for record in self.__cloudflare_list_zone_records(zobj['id']):
                    zone['records'].append({
                        'id': get_resource_id('cfr', zobj['id'], ['{}={}'.format(k, v) for k, v in record.items()]),
                        'zone_id': zone['zone_id'],
                        'name': record['name'],
                        'value': record['value'],
                        'type': record['type']
                    })

                if len(zone['records']) > 0:
                    zones.append(zone)
            except CloudFlareError:
                self.log.exception('Failed getting records for CloudFlare zone {}'.format(zobj['name']))

        return zones

    # region Helper functions for CloudFlare
    def __cloudflare_request(self, path, args=dict):
        """Helper function to interact with the CloudFlare API.

        Args:
            path (`str`): URL endpoint to communicate with
            args (:obj:`dict` of `str`: `str`): A dictionary of arguments for the endpoint to consume

        Returns:
            `dict`
        """
        if not self.cloudflare_initialized:
            self.cloudflare_session = requests.Session()
            self.cloudflare_session.headers.update({
                'X-Auth-Email': self.cloudflare_email,
                'X-Auth-Key': self.cloudflare_api_key,
                'Content-Type': 'application/json'
            })
            self.cloudflare_initialized = True

        if 'per_page' not in args:
            args['per_page'] = 100

        response = self.cloudflare_session.get(self.cloudflare_endpoint + path, params=args)
        if response.status_code != 200:
            raise CloudFlareError('Request failed: {}'.format(response.text))

        return response.json()

    def __cloudflare_list_zones(self, **kwargs):
        """Helper function to list all zones registered in the CloudFlare system. Returns a `list` of the zones

        Args:
            **kwargs (`dict`): Extra arguments to pass to the API endpoint

        Returns:
            `list` of `dict`
        """
        done = False
        zones = []
        page = 1

        while not done:
            kwargs['page'] = page
            response = self.__cloudflare_request('/zones', kwargs)
            info = response['result_info']

            if 'total_pages' not in info or page == info['total_pages']:
                done = True
            else:
                page += 1

            zones += response['result']

        return zones

    def __cloudflare_list_zone_records(self, zoneID, **kwargs):
        """Helper function to list all records on a CloudFlare DNS Zone. Returns a `dict` containing the records and
        their information.

        Args:
            zoneID (`int`): Internal CloudFlare ID of the DNS zone
            **kwargs (`dict`): Additional arguments to be consumed by the API endpoint

        Returns:
            :obj:`dict` of `str`: `dict`
        """
        done = False
        records = {}
        page = 1

        while not done:
            kwargs['page'] = page
            response = self.__cloudflare_request('/zones/{}/dns_records'.format(zoneID), kwargs)
            info = response['result_info']

            # Check if we have received all records, and if not iterate over the result set
            if 'total_pages' not in info or page == info['total_pages']:
                done = True
            else:
                page += 1

            for record in response['result']:
                if record['name'] in records:
                    records[record['name']]['value'] = sorted(records[record['name']]['value'] + [record['content']])
                else:
                    records[record['name']] = {
                        'name': record['name'],
                        'value': sorted([record['content']]),
                        'type': record['type']
                    }

        return list(records.values())
    # endregion
