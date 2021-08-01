"""
Simple fetch provider for ldap.

This fetcher also serves as an example how to build custom OPAL Fetch Providers.
"""
from typing import Optional, List

from distutils.util import strtobool
from pydantic import BaseModel, Field
from tenacity import wait, stop, retry_unless_exception_type

from opal_common.fetcher.fetch_provider import BaseFetchProvider
from opal_common.fetcher.events import FetcherConfig, FetchEvent
from opal_common.logger import logger

import ldap3

class LdapConnectionParams(BaseModel):
    # TODO
    """
    if one does not want to pass all Ldap arguments in the dsn (in OPAL - the url is the dsn),
    one can also use this dict to pass specific arguments.
    """
    root: Optional[str] = Field(None, description="the root dn")
    search: Optional[str] = Field(None, description="the search query")
    user: Optional[str] = Field(None, description="user name used to authenticate")
    password: Optional[str] = Field(None, description="password used to authenticate")
    host: Optional[str] = Field(None, description="database host address (defaults to UNIX socket if not provided)")
    port: Optional[str] = Field(None, description="connection port number (defaults to 5432 if not provided)")
    tls: Optional[str] = Field(None, description="whether to enable tls")


class LdapFetcherConfig(FetcherConfig):
    # TODO
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
    connection_params: Optional[LdapConnectionParams] = Field(None, description="these params can override or complement parts of the dsn (connection string)")
    query: str = Field(..., description="the query to run against Ldap in order to fetch the data")
    fetch_one: bool = Field(False, description="whether we fetch only one row from the results of the SELECT query")


class LdapFetchEvent(FetchEvent):
    # TODO
    """
    A FetchEvent shape for the Ldap Fetch Provider.

    When writing a custom provider, you must create a custom FetchEvent subclass, just like this class.
    In your own class, you must set the value of the `fetcher` key to be your custom provider class name.
    """
    fetcher: str = "LdapFetchProvider"
    config: LdapFetcherConfig = None


class LdapFetchProvider(BaseFetchProvider):
    # TODO
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
        'retry': retry_unless_exception_type(DataError), # query error (i.e: invalid table, etc)
        'reraise': True
    }

    def __init__(self, event: LdapFetchEvent) -> None:
        if event.config is None:
            event.config = LdapFetcherConfig()
        super().__init__(event)
        self._connection: Optional[asyncpg.Connection] = None
        self._transaction: Optional[Transaction] = None

    def parse_event(self, event: FetchEvent) -> LdapFetchEvent:
        return LdapFetchEvent(**event.dict(exclude={"config"}), config=event.config)

    async def __aenter__(self):
        self._event: LdapFetchEvent # type casting

        dsn: str = self._event.url
        connection_params: dict = {} if self._event.config.connection_params is None else self._event.config.connection_params.dict(exclude_none=True)

        # connect to the Ldap database
        self._connection: asyncpg.Connection = await asyncpg.connect(dsn, **connection_params)
        # start a readonly transaction (we don't want OPAL client writing data due to security!)
        self._transaction: Transaction = self._connection.transaction(readonly=True)
        await self._transaction.__aenter__()

        return self

    async def __aexit__(self, exc_type=None, exc_val=None, tb=None):
        # End the transaction
        if self._transaction is not None:
            await self._transaction.__aexit__(exc_type, exc_val, tb)
        # Close the connection
        if self._connection is not None:
            await self._connection.close()

    async def _fetch_(self):
        self._event: LdapFetchEvent # type casting
        
        if self._event.config is None:
            logger.warning("incomplete fetcher config: Ldap data entries require a query to specify what data to fetch!")
            return
        
        logger.debug(f"{self.__class__.__name__} fetching from {self._url}")

        if self._event.config.fetch_one:
            row = await self._connection.fetchrow(self._event.config.query)
            return [row]
        else:
            return await self._connection.fetch(self._event.config.query)

    async def _process_(self, records: List[asyncpg.Record]):
        self._event: LdapFetchEvent # type casting
        
        # when fetch_one is true, we want to return a dict (and not a list)
        if self._event.config.fetch_one:
            if records and len(records) > 0:
                # we transform the asyncpg record to a dict that we can be later serialized to json
                return dict(records[0])
            else:
                return {}
        else:
            # we transform the asyncpg records to a list-of-dicts that we can be later serialized to json
            return [dict(record) for record in records]
