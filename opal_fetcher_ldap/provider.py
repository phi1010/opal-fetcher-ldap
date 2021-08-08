"""
Simple fetch provider for ldap.

This fetcher also serves as an example how to build custom OPAL Fetch Providers.
"""
import json
from typing import Optional, List, Dict

from distutils.util import strtobool
from pydantic import BaseModel, Field
from tenacity import wait, stop, retry_unless_exception_type

from opal_common.fetcher.fetch_provider import BaseFetchProvider
from opal_common.fetcher.events import FetcherConfig, FetchEvent
from opal_common.logger import logger

import ldap3


class LdapConnectionParams(BaseModel):
    """
    if one does not want to pass all Ldap arguments in the dsn (in OPAL - the url is the dsn),
    one can also use this dict to pass specific arguments.
    """
    user: Optional[str] = Field(None, description="user name used to authenticate")
    password: Optional[str] = Field(None, description="password used to authenticate")
    url: str = Field(None, description="database host address (e.g. ldaps://localhost:636)")


class LdapFetcherConfig(FetcherConfig):
    """
    Config for LdapFetchProvider, instance of `FetcherConfig`.
    
    When an OPAL client receives an update, it contains a list of `DataSourceEntry` objects.
    Each `DataSourceEntry` has a `config` key - which is usually an instance of a subclass of `FetcherConfig`.
    
    When writing a custom provider, you must:
    - derive your class (inherit) from FetcherConfig
    - override the `fetcher` key with your fetcher class name
    - (optional): add any fields relevant to a data entry of your fetcher. 
        - In this example: since we pull data from LdapQL - we added a `query` key to hold the SQL query.
    """
    fetcher: str = "LdapFetchProvider"
    connection_params: Optional[LdapConnectionParams] = Field(None,
                                                              description="these params can override or complement parts of the dsn (connection string)")
    root: str = Field(None, description="the root dn")
    search: str = Field(None, description="the search query")
    attributes: List[str] = Field(None, description="list of attributes")


class LdapFetchEvent(FetchEvent):
    """
    A FetchEvent shape for the Ldap Fetch Provider.

    When writing a custom provider, you must create a custom FetchEvent subclass, just like this class.
    In your own class, you must set the value of the `fetcher` key to be your custom provider class name.
    """
    fetcher: str = "LdapFetchProvider"
    config: LdapFetcherConfig = None


class LdapFetchProvider(BaseFetchProvider):
    """
    An OPAL fetch provider for ldap.

    When writing a custom provider, you must:
    - derive your provider class (inherit) from BaseFetchProvider
    - create a custom config class, as shown above, that derives from FetcherConfig
    - create a custom event class, as shown above, that derives from FetchEvent

    At minimum, your custom provider class must implement:
    - __init__() - and call super().__init__(event)
    - parse_event() - this method gets a `FetchEvent` object and must transform this object to *your own custom event class*.
        - Notice that `FetchEvent` is the base class
        - Notice that `LdapFetchEvent` is the custom event class
    - _fetch_() - your custom fetch method, can use the data from your event
    and config to figure out *what and how to fetch* and actually do it.
    - _process_() - if your fetched data requires some processing, you should do it here.
        - The return type from this method must be json-able, i.e: can be serialized to json.
    
    You may need to implement:
    - __aenter__() - if your provider has state that needs to be cleaned up,
    (i.e: http session, Ldap connection, etc) the state may be initialized in this method.
    - __aexit__() - if you initialized stateful objects (i.e: acquired resources) in your __aenter__, you must release them in __aexit__
    """
    RETRY_CONFIG = {
        'wait': wait.wait_random_exponential(),
        'stop': stop.stop_after_attempt(10),
        # 'retry': retry_unless_exception_type(SomeError), # query error (i.e: invalid table, etc)
        'reraise': True
    }

    def __init__(self, event: LdapFetchEvent) -> None:
        if event.config is None:
            event.config = LdapFetcherConfig()
        super().__init__(event)
        self._server: Optional[ldap3.Server] = None
        self._connection: Optional[ldap3.Connection] = None

    def parse_event(self, event: FetchEvent) -> LdapFetchEvent:
        return LdapFetchEvent(**event.dict(exclude={"config"}), config=event.config)

    async def __aenter__(self):
        self._event: LdapFetchEvent  # type casting
        # TODO should we use this?
        dsn: str = self._event.url
        connection_params = self._event.config.connection_params

        # connect to the Ldap database
        connection_params: LdapConnectionParams
        self._server = ldap3.Server(host=connection_params.url)
        self._connection = ldap3.Connection(
            server=self._server,
            user=connection_params.user,
            password=connection_params.password,
            auto_bind=True,
            auto_range=True,
            read_only=True,
        )
        # TODO use a threadpoolexecutor for this?
        self._connection.open()

        return self

    async def __aexit__(self, exc_type=None, exc_val=None, tb=None):
        if self._connection is not None:
            # unbind: disconnect and close the connection
            self._connection.unbind()

    async def _fetch_(self):
        self._event: LdapFetchEvent  # type casting

        if self._event.config is None:
            logger.warning(
                "incomplete fetcher config: Ldap data entries require a query to specify what data to fetch!")
            return

        logger.debug(f"{self.__class__.__name__} fetching from {self._url}")
        root_dn = self._event.config.root
        search_query = self._event.config.search
        attributes = self._event.config.attributes
        # This should also support MS AD with 1000+ entries
        return self._connection.extend.standard.paged_search(
            search_base=root_dn,
            search_filter=search_query,
            attributes=attributes,
            paged_size=100,
        )

    async def _process_(self, records: List[Dict]):
        self._event: LdapFetchEvent  # type casting
        attributes = self._event.config.attributes
        # we transform the asyncpg records to a list-of-dicts that we can be later serialized to json
        values = {
            (dn := record)["dn"]:
                {
                    attribute:
                        record["attributes"][attribute]
                    for attribute in attributes
                    if attribute in record["attributes"]
                }
            for record in records
            if record["type"] == "searchResEntry"}
        logger.info(json.dumps(values))
        return values
