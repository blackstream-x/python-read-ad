# -*- coding: utf-8 -*-

"""

read_ad

A lightweight wrapper around COM support
for Active Directory readonly access.

Based on original version 0.6.7 by Tim Golden
(see <http://timgolden.me.uk/python/active_directory.html>)
with a few cherry-picks from the current implementation
(<https://github.com/tjguk/active_directory/blob/master/active_directory.py>)

Rewrite for Python3 with minimized dependencies
by Rainer Schwarzbach, 2021-01-28

License: MIT

"""


import datetime
import logging
import re
import struct

import win32com.client
import win32security


#
# Global constants and cache
#


BASE_TIME = datetime.datetime(1601, 1, 1)
TIME_NEVER_HIGH_PART = 0x7fffffff
TIME_NEVER_KEYWORD = '<never>'

ADO_COMMAND = 'ADODB.Command'
ADO_CONNECTION = 'ADODB.Connection'
CONNECTION_PROVIDER = 'ADsDSOObject'
CONNECTION_TARGET = 'Active Directory Provider'

CACHE_KEY_CONNECTION = '_Connection_'
CACHE_KEY_ROOT = '_ActiveDirectoryRoot_'

GLOBAL_CACHE = {}


#
# Helper functions
#


def connection():
    """Open a new connection or return the cached existing one"""
    try:
        existing_connection = GLOBAL_CACHE[CACHE_KEY_CONNECTION]
    except KeyError:
        new_connection = win32com.client.Dispatch(ADO_CONNECTION)
        new_connection.Provider = CONNECTION_PROVIDER
        new_connection.Open(CONNECTION_TARGET)
        return GLOBAL_CACHE.setdefault(CACHE_KEY_CONNECTION, new_connection)
    #
    if not existing_connection.state:
        # Reopen the connection if necessary
        existing_connection.Open(CONNECTION_TARGET)
    #
    return existing_connection


def signed_to_unsigned(number):
    """Convert a signed integer to an unsigned one,
    adapted from the current upstream implementation
    <https://github.com/tjguk/active_directory/
     blob/master/active_directory.py>
    """
    if number >= 0:
        return number
    #
    return struct.unpack('L', struct.pack('l', number))[0]


def convert_to_datetime(ad_time):
    """Return a datetime from active directory.

    numeric_date is the number of 100-nanosecond intervals
    since 12:00 AM January 1, 1601, see
    <https://ldapwiki.com/wiki/LargeInteger#section-LargeInteger-NumericDate>

    Return 'never' for dates with a high part of 0x7fffffff.
    If the time still exceeds the python datetime range,
    return the maximum supported datetime.
    """
    if ad_time is None:
        return None
    #
    high_part, low_part = [signed_to_unsigned(part) for part in
                           (ad_time.HighPart, ad_time.LowPart)]
    if high_part == TIME_NEVER_HIGH_PART:
        return TIME_NEVER_KEYWORD
    #
    numeric_date = (high_part << 32) + low_part
    delta = datetime.timedelta(microseconds=numeric_date / 10)
    try:
        return BASE_TIME + delta
    except OverflowError:
        return datetime.datetime.max
    #


def convert_to_guid(item):
    """Return a GUID from an LDAP entry's property"""
    if item is None:
        return None
    #
    guid = convert_to_hex(item)
    slice_borders = (8, 12, 16, 20)
    return '{%s}' % '-'.join(
        guid[slice(*pair)]
        for pair in zip((None, *slice_borders), (*slice_borders, None)))


def convert_to_hex(item):
    """Return a hexadecimal representation of binary data"""
    if item is None:
        return None
    #
    return ''.join('%02x' % (char & 0xff) for char in bytes(item))


def convert_to_sid(item):
    """Return a PySID from binary data"""
    if item is None:
        return None
    #
    return win32security.SID(bytes(item))


#
# Classes
#


class UnsignedIntegerMapping():

    """Mapping of names to unsigned integer numbers
    supporting lookups in each direction
    """

    def __init__(self, **kwargs):
        """Initialize the internal mappings
        from the keyword arguments
        """
        self.__by_names = {}
        self.__by_numbers = {}
        for name, number in kwargs.items():
            number = signed_to_unsigned(number)
            self.__by_names[name] = number
            self.__by_numbers[number] = name

    def get_name(self, number):
        """Return the name assigned to the number"""
        if number is None:
            return None
        #
        return self.__by_numbers[signed_to_unsigned(number)]

    def items(self):
        """Items: by name"""
        return self.__by_names.items()

    def __getitem__(self, item):
        """Get number by name or name by number"""
        try:
            return self.__by_names[item]
        except KeyError:
            return self.__by_numbers[signed_to_unsigned(item)]
        #

    def __repr__(self):
        """Return a readable presentation of the entire mapping"""
        return '<%s: %s>' % (
            self.__class__.__name__,
            ', '.join(
                '%s <=> %s' % (name, number)
                for (name, number) in self.items()))


class FlagsMapping(UnsignedIntegerMapping):

    """Mapping of flags to bitmasks"""

    def get_flag_names(self, number):
        """Return a set of flag names
        matching the number via bitmask
        """
        if number is None:
            return None
        #
        unsigned_number = signed_to_unsigned(number)
        return set(
            name for (name, bitmask) in self.items()
            if unsigned_number & bitmask == bitmask)


GROUP_TYPES = FlagsMapping(
    GLOBAL_GROUP=0x00000002,
    DOMAIN_LOCAL_GROUP=0x00000004,
    LOCAL_GROUP=0x00000004,
    UNIVERSAL_GROUP=0x00000008,
    SECURITY_ENABLED=0x80000000)

AUTHENTICATION_TYPES = FlagsMapping(
    SECURE_AUTHENTICATION=0x01,
    USE_ENCRYPTION=0x02,
    USE_SSL=0x02,
    READONLY_SERVER=0x04,
    PROMPT_CREDENTIALS=0x08,
    NO_AUTHENTICATION=0x10,
    FAST_BIND=0x20,
    USE_SIGNING=0x40,
    USE_SEALING=0x80,
    USE_DELEGATION=0x100,
    SERVER_BIND=0x200,
    AUTH_RESERVED=0x80000000)

SAM_ACCOUNT_TYPES = UnsignedIntegerMapping(
    SAM_DOMAIN_OBJECT=0x0,
    SAM_GROUP_OBJECT=0x10000000,
    SAM_NON_SECURITY_GROUP_OBJECT=0x10000001,
    SAM_ALIAS_OBJECT=0x20000000,
    SAM_NON_SECURITY_ALIAS_OBJECT=0x20000001,
    SAM_USER_OBJECT=0x30000000,
    SAM_NORMAL_USER_ACCOUNT=0x30000000,
    SAM_MACHINE_ACCOUNT=0x30000001,
    SAM_TRUST_ACCOUNT=0x30000002,
    SAM_APP_BASIC_GROUP=0x40000000,
    SAM_APP_QUERY_GROUP=0x40000001,
    SAM_ACCOUNT_TYPE_MAX=0x7fffffff)

USER_ACCOUNT_CONTROL = FlagsMapping(
    ADS_UF_SCRIPT=0x00000001,
    ADS_UF_ACCOUNTDISABLE=0x00000002,
    ADS_UF_HOMEDIR_REQUIRED=0x00000008,
    ADS_UF_LOCKOUT=0x00000010,
    ADS_UF_PASSWD_NOTREQD=0x00000020,
    ADS_UF_PASSWD_CANT_CHANGE=0x00000040,
    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED=0x00000080,
    ADS_UF_TEMP_DUPLICATE_ACCOUNT=0x00000100,
    ADS_UF_NORMAL_ACCOUNT=0x00000200,
    ADS_UF_INTERDOMAIN_TRUST_ACCOUNT=0x00000800,
    ADS_UF_WORKSTATION_TRUST_ACCOUNT=0x00001000,
    ADS_UF_SERVER_TRUST_ACCOUNT=0x00002000,
    ADS_UF_DONT_EXPIRE_PASSWD=0x00010000,
    ADS_UF_MNS_LOGON_ACCOUNT=0x00020000,
    ADS_UF_SMARTCARD_REQUIRED=0x00040000,
    ADS_UF_TRUSTED_FOR_DELEGATION=0x00080000,
    ADS_UF_NOT_DELEGATED=0x00100000,
    ADS_UF_USE_DES_KEY_ONLY=0x00200000,
    ADS_UF_DONT_REQUIRE_PREAUTH=0x00400000,
    ADS_UF_PASSWORD_EXPIRED=0x00800000,
    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION=0x01000000)


class RecordSet():

    """Simple wrapper around an ADO Recordset, see
    <https://docs.microsoft.com/windows/win32/adsi
     /searching-with-activex-data-objects-ado>
    """

    search_properties = dict(
        Asynchronous=True,
        Timeout=1)

    def __init__(self, record):
        """Store the fields of the record by name"""
        self.__fields = {}
        for field_number in range(record.Fields.Count):
            field = record.Fields.Item(field_number)
            self.__fields[field.Name] = field.Value
        #

    @classmethod
    def query(cls, query_string, **kwargs):
        """Yield RecordSet objects from each result of an ADO query.
        ADO command properties may be specified as keyword arguments.
        Underscores in the keywords are replaced by spaces.
        """
        command = win32com.client.Dispatch(ADO_COMMAND)
        command.ActiveConnection = connection()
        #
        search_properties = dict(cls.search_properties)
        search_properties.update(kwargs)
        for key, value in search_properties.items():
            command.Properties(key.replace('_', ' ')).Value = value
        #
        command.CommandText = query_string
        # pylint: disable=no-member ; false positive for com_error
        try:
            result_set = command.Execute()[0]
        except win32com.client.pywintypes.com_error as error:
            raise ValueError(
                '%r\n\nPossibly faulty query string:\n%s' % (
                    error, query_string)) from error
        #
        # pylint: enable
        while not result_set.EOF:
            yield cls(result_set)
            result_set.MoveNext()
        #

    def dump_fields(self):
        """Yield all field names and values as tuples"""
        for name, item in self.__fields.items():
            yield (name, item)
        #

    def __getattr__(self, name):
        """Allow access to fields via attributes"""
        try:
            return self.__fields[name]
        except KeyError as error:
            raise AttributeError(
                '%r object has no attribute %r' % (
                    self.__class__.__name__, name)) from error
        #

    def __repr__(self):
        """Return a readable presentation of the entire record"""
        return '<%s: %s>' % (
            self.__class__.__name__,
            ', '.join('%s=%r' % field for field in self.dump_fields()))

    def __str__(self):
        """Return a presentation of the entire record
        suitable for output
        """
        return '{\n%s\n}' % (
            ', '.join('  %s=%r' % field for field in self.dump_fields()))


class PathComponent:

    """Component of an LDAP path"""

    prx_equals = re.compile(r'(?<!\\)=')

    def __init__(self, keyword, value):
        """Initialize from the keyword and value arguments"""
        keyword = keyword.strip().lower()
        value = value.strip()
        if not keyword or not value:
            raise ValueError(
                "'%s=%s' is not a valid path component!" % (keyword, value))
        #
        self.__keyword = keyword
        self.__value = value

    @property
    def keyword(self):
        """Return the keyword"""
        return self.__keyword

    @property
    def value(self):
        """Return the value"""
        return self.__value

    @classmethod
    def from_string(cls, string):
        """Construct a PathComponent from the given string"""
        try:
            (keyword, value) = cls.prx_equals.split(string)
        except ValueError as error:
            raise ValueError(
                '%r is not a valid path component!' % string) from error
        #
        return cls(keyword, value)

    def __eq__(self, other):
        """Rich comparison: equals"""
        return str(self) == str(other)

    def __hash__(self):
        """Return a hash over the normal string representation"""
        return hash(str(self))

    def __repr__(self):
        """Return a string representation"""
        return '<%s: %s>' % (self.__class__.__name__, str(self))

    def __str__(self):
        """Return a normalized string representation"""
        return '%s=%s' % (self.__keyword, self.__value)


class LdapPath:

    """Simple access to the parts of an LDAP path
    (distinguished name)
    """

    ldap_url_prefix = 'LDAP://'
    prx_comma = re.compile(r'(?<!\\),')

    def __init__(self, *parts):
        """Keep a tuple of components"""
        if not parts:
            raise ValueError('Empty paths are not supported.')
        #
        components = []
        for single_part in parts:
            if not isinstance(single_part, PathComponent):
                single_part = PathComponent.from_string(single_part)
            #
            components.append(single_part)
        #
        self.__components = tuple(components)

    @property
    def components(self):
        """Return the components tuple"""
        return self.__components

    @property
    def rdn(self):
        """Return the relative distinguished name
        (i.e. value of the first part)
        """
        return self[0].value

    @property
    def url(self):
        """Return an LDAP URL from the path"""
        return '%s%s' % (self.ldap_url_prefix, str(self))

    @classmethod
    def from_string(cls, string):
        """Construct an LdapPath from the given string"""
        if string.upper().startswith(cls.ldap_url_prefix):
            string = string[len(cls.ldap_url_prefix):]
        #
        try:
            return cls(*cls.prx_comma.split(string))
        except ValueError as error:
            raise ValueError(
                '%r is not a valid LDAP path!' % string) from error
        #

    def __eq__(self, other):
        """Rich comparison: equals"""
        return str(self) == str(other)

    def __getitem__(self, index):
        """Return the path component at position index"""
        return self.__components[index]

    def __hash__(self):
        """Return a hash over the distinguished name"""
        return hash(str(self))

    def __iter__(self):
        """Return an iterator over the components"""
        return iter(self.__components)

    def __len__(self):
        """Return the number of components"""
        return len(self.__components)

    def __repr__(self):
        """Return the distinguished name prefixed with the
        class name
        """
        return '<%s: %s>' % (self.__class__.__name__, str(self))

    def __str__(self):
        """Return the distinguished name"""
        return ','.join(str(part) for part in self.__components)


class SearchFilter:

    """Simple object holding search parameters"""

    def __init__(self, primary_key_name, **fixed_parameters):
        """Store primary key name and fixed parameters"""
        self.__primary_key_name = primary_key_name
        self.__fixed_parameters = fixed_parameters

    def execute_query(self, ldap_path, *args, **kwargs):
        """Build an SQL statement and execute a query
        from the provided LDAP path.
        Yield RecordSet objects.
        """
        sql_statement = '\n'.join([
            'SELECT ADsPath, userAccountControl',
            'FROM %r' % ldap_path.url,
            self.where_clause(*args, **kwargs)])
        for result in RecordSet.query(sql_statement):
            yield result
        #

    def where_clause(self, *args, **kwargs):
        """Build a WHERE clause for an
        LDAP query SQL statement (if necessary)
        """
        kwargs.update(self.__fixed_parameters)
        primary_key_value = kwargs.pop('_primary_key_', None)
        if primary_key_value and self.__primary_key_name:
            kwargs[self.__primary_key_name] = primary_key_value
        #
        where_clauses = list(args) + [
            '%s=%r' % (key, str(value))
            for (key, value) in kwargs.items()]
        if where_clauses:
            return 'WHERE %s' % ' AND '.join(where_clauses)
        #
        return ''

    def __repr__(self):
        """Return a string representation"""
        return '<%s using %s, with fixed value(s) %s>' % (
            self.__class__.__name__,
            self.__primary_key_name,
            ', '.join(
                '%s=%r' % item for item in self.__fixed_parameters.items()))


SEARCH_FILTERS = {
    'computer': SearchFilter(
        'cn',
        objectCategory='Computer'),
    'group': SearchFilter(
        'cn',
        objectCategory='group'),
    'ou': SearchFilter(
        'ou',
        objectClass='organizationalUnit'),
    'public_folder': SearchFilter(
        'displayName',
        objectClass='publicFolder'),
    'userid': SearchFilter(
        'sAMAccountName',
        objectCategory='Person',
        objectClass='User')}


class LdapEntry:

    """Store a subset of an LDAP entry's properties.
    Should be instantiated via the produce_entry()
    factory function.
    """

    additional_conversions = {}
    property_adspath = 'ADsPath'
    property_ntsecuritydescriptor = 'nTSecurityDescriptor'
    property_guid = 'GUID'
    property_parent = 'Parent'
    ignore_properties = {property_ntsecuritydescriptor}
    additional_properties = {
        property_adspath, property_guid, property_parent}

    def __init__(self, com_object):
        """Store properties form the provided COM object.
        The property names are determined from the schema,
        plus the required (cls.)additional_properties,
        minus the preformance-degrading (cls.)ignore_properties.
        """
        schema = win32com.client.GetObject(com_object.Schema)
        property_names = tuple(
            single_property for single_property in
            set(schema.MandatoryProperties)
            | set(schema.OptionalProperties)
            | self.additional_properties
            if single_property not in self.ignore_properties)
        conversions = dict(
            objectGUID=convert_to_guid,
            uSNChanged=convert_to_datetime,
            uSNCreated=convert_to_datetime,
            replicationSignature=convert_to_hex)
        conversions.update(self.additional_conversions)
        self.__case_translation = dict()
        self.__property_cache = dict()
        self.__empty_properties = set()
        for name in property_names:
            try:
                com_property = getattr(com_object, name)
            except AttributeError:
                logging.warning('Property %r not found', name)
                continue
            #
            self.__case_translation[name.lower()] = name
            if com_property is None:
                self.__empty_properties.add(name)
                continue
            #
            try:
                com_property = conversions[name](com_property)
            except KeyError:
                pass
            #
            self.__add_property(name, com_property)
        #
        self.items = self.__property_cache.items

    @property
    def empty_properties(self):
        """Return a sorted list of empty properties' names"""
        return sorted(self.__empty_properties)

    @property
    def parent(self):
        """Return this object's parent LDAP entry"""
        return produce_entry(self[self.property_parent])

    @property
    def path(self):
        """Return the COM object's ADsPath"""
        return LdapPath.from_string(self[self.property_adspath])

    def __add_property(self, name, value):
        """Add a property value only if it is not a
        COM_Object or a memoryview (or a collection of those)
        """
        if isinstance(value, (list, tuple)):
            if value and isinstance(
                    value[0], (memoryview, win32com.client.CDispatch)):
                return
            #
        #
        if not isinstance(value, (memoryview, win32com.client.CDispatch)):
            self.__property_cache[name] = value
        #

    def child(self, single_path_cmponent):
        """Return the relative child of this entry. The relative_path
        is inserted into this entry's LDAP path to make a coherent
        LDAP path for a child entry, eg:

        users = root.child('cn=Users')
        """
        return produce_entry(LdapPath(single_path_cmponent, *self.path))

    def print_dump(self):
        """Print all non-empty properties in
        (case-sensitive) alphabetical order
        """
        print('%r\n{' % self)
        for (name, value) in sorted(self.items()):
            print('  %s \u2192 %r' % (name, value))
        #
        print('}')

    def __eq__(self, other):
        """Compare the GUIDs"""
        return self[self.property_guid] == other[self.property_guid]

    def __getattr__(self, name):
        """Instance attribute access to the com object's properties
        via item access
        """
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(
                '%r object has no attribute %r' % (
                    self.__class__.__name__, name)) from error
        #

    def __getitem__(self, name):
        """Access the properties as dict members,
        using case-insensitive names
        """
        translated_name = self.__case_translation[name.lower()]
        try:
            return self.__property_cache[translated_name]
        except KeyError:
            if translated_name in self.__empty_properties:
                return None
            #
        #
        raise KeyError(name)

    def __hash__(self):
        """Identify by the GUID"""
        return hash(self[self.property_guid])

    def __repr__(self):
        """Return a representation with the class name
        and the path
        """
        return "<%s: %s>" % (self.__class__.__name__, str(self.path))

    def __str__(self):
        """Return the path"""
        return str(self.path)


class User(LdapEntry):

    """Active Directory user with an additional bool property
    (account_disabled)
    """

    additional_conversions = dict(
        accountExpires=convert_to_datetime,
        badPasswordTime=convert_to_datetime,
        lastLogoff=convert_to_datetime,
        lastLogon=convert_to_datetime,
        lastLogonTimestamp=convert_to_datetime,
        lockoutTime=convert_to_datetime,
        msExchMailboxGuid=convert_to_guid,
        objectSid=convert_to_sid,
        pwdLastSet=convert_to_datetime,
        sAMAccountType=SAM_ACCOUNT_TYPES.get_name,
        userAccountControl=USER_ACCOUNT_CONTROL.get_flag_names)

    @property
    def account_disabled(self):
        """Return True if the account is disabled"""
        return 'ADS_UF_ACCOUNTDISABLE' in self.userAccountControl


class Group(LdapEntry):

    """Active Directory group"""

    additional_conversions = dict(
        groupType=GROUP_TYPES.get_flag_names,
        objectSid=convert_to_sid,
        sAMAccountType=SAM_ACCOUNT_TYPES.get_name)

    def walk(self):
        """Yield a tuple of (self, subgroups_list, users_list)
        and repeat that (recursively) for each subgroup.
        """
        member_paths = self.member or []
        if isinstance(member_paths, str):
            member_paths = [member_paths]
        #
        groups_list = []
        users_list = []
        for single_path in member_paths:
            child_entry = produce_entry(single_path)
            if isinstance(child_entry, self.__class__):
                groups_list.append(child_entry)
            elif isinstance(child_entry, User):
                users_list.append(child_entry)
            #
        #
        yield (self, groups_list, users_list)
        for child_group in groups_list:
            for result in child_group.walk():
                yield result
            #
        #


class Computer(LdapEntry):

    """Active Directory computer"""

    additional_conversions = dict(
        accountExpires=convert_to_datetime,
        badPasswordTime=convert_to_datetime,
        lastLogoff=convert_to_datetime,
        lastLogon=convert_to_datetime,
        lastLogonTimestamp=convert_to_datetime,
        objectSid=convert_to_sid,
        pwdLastSet=convert_to_datetime,
        sAMAccountType=SAM_ACCOUNT_TYPES.get_name,
        userAccountControl=USER_ACCOUNT_CONTROL.get_flag_names)


class OrganizationalUnit(LdapEntry):

    """Active Directory Organisational unit"""

    user_search_fields = ('sAMAccountName', 'displayName', 'cn')

    def find(self, *args, **kwargs):
        """Return an LdapEntry for the first matching
        search result.
        """
        for found_path in self.search(*args, **kwargs):
            return produce_entry(found_path)
        #
        return None

    def find_user(self, *args, **kwargs):
        """Return a User object for the first matching
        search result.
        """
        args_list = list(args)
        try:
            name = args_list.pop(0)
        except IndexError:
            pass
        else:
            user_search = []
            for field_name in self.user_search_fields:
                if field_name not in kwargs:
                    user_search.append('%s=%r' % (field_name, str(name)))
                #
            #
            if user_search:
                args_list = [' OR '.join(user_search)] + args_list
            #
        #
        for found_path in self.search(
                *args_list, search_filter=SEARCH_FILTERS['userid'], **kwargs):
            return produce_entry(found_path)
        #

    def search(self, *args, active=None, search_filter=None, **kwargs):
        """Yield LDAP paths (plain strings) for all found Entries.

        If 'active' is set to True or False explicitly,
        yield the path only if the userAccountControl
        property value matches the desired state.

        if 'search_filter' is not set, determine a search filter
        automatically.
        """
        if not isinstance(search_filter, SearchFilter):
            for (keyword, candidate) in SEARCH_FILTERS.items():
                try:
                    value = kwargs.pop(keyword)
                except KeyError:
                    continue
                #
                kwargs['_primary_key_'] = value
                search_filter = candidate
                break
            else:
                search_filter = SearchFilter(None)
            #
        #
        if active is None:
            for result in search_filter.execute_query(
                    self.path, *args, **kwargs):
                yield result.ADsPath
            #
            return
        #
        bitmask = USER_ACCOUNT_CONTROL['ADS_UF_ACCOUNTDISABLE']
        desired_state = bitmask
        if active:
            desired_state = 0
        #
        for result in search_filter.execute_query(self.path, *args, **kwargs):
            try:
                if result.userAccountControl & bitmask == desired_state:
                    yield result.ADsPath
                #
            except TypeError:
                # no userAccountControl property
                yield result.ADsPath
            #
        #


class DomainDNS(OrganizationalUnit):

    """Active Directory Domain DNS"""

    additional_conversions = dict(
        creationTime=convert_to_datetime,
        dSASignature=convert_to_hex,
        forceLogoff=convert_to_datetime,
        lockoutDuration=convert_to_datetime,
        lockoutObservationWindow=convert_to_datetime,
        maxPwdAge=convert_to_datetime,
        minPwdAge=convert_to_datetime,
        modifiedCount=convert_to_datetime,
        modifiedCountAtLastProm=convert_to_datetime,
        objectSid=convert_to_sid)


class PublicFolder(LdapEntry):

    """Active Directory public folder"""

    ...


#
# Module-level functions
#


def produce_entry(ldap_path, lazy=True):
    """Produce an LdapEntry or subclass instance
    from the given LDAP path.
    If lazy is not set to False explicitly,
    the entry associated with the provided LDAP path
    is returned from the global cache if it exists.
    """
    if not isinstance(ldap_path, LdapPath):
        ldap_path = LdapPath.from_string(ldap_path)
    #
    if lazy and ldap_path in GLOBAL_CACHE:
        return GLOBAL_CACHE[ldap_path.url]
    #
    try:
        com_object = win32com.client.GetObject(ldap_path.url)
    except Exception as error:
        raise ValueError(
            'Problem with path %s: %s' % (ldap_path, error)) from error
        #
    #
    object_class_lower = com_object.Class.lower()
    for ldap_entry_class in (
            User, Group, DomainDNS,
            OrganizationalUnit, Computer, PublicFolder):
        if ldap_entry_class.__name__.lower() == object_class_lower:
            return GLOBAL_CACHE.setdefault(ldap_path.url,
                                           ldap_entry_class(com_object))
        #
    #
    raise ValueError(
        'Problem with object %s: No matching class %r found' % (
            com_object, object_class_lower))


def root(server=None):
    """Return a cached entry referring to the
    root of the logged-on active directory tree.
    """
    try:
        return GLOBAL_CACHE[GLOBAL_CACHE[CACHE_KEY_ROOT]]
    except KeyError:
        root_dse_path = 'rootDSE'
        if server:
            root_dse_path = '%s/%s' % (server, root_dse_path)
        #
        ldap_root = win32com.client.GetObject(
            '%s%s' % (LdapPath.ldap_url_prefix, root_dse_path))
        default_naming_context = ldap_root.Get("defaultNamingContext")
        ldap_root_path = LdapPath.from_string(default_naming_context)
        GLOBAL_CACHE[CACHE_KEY_ROOT] = ldap_root_path.url
        return produce_entry(ldap_root_path)
    #


def find(*args, **kwargs):
    """Find an LDAP entry.
    Determine the type by the keyword argument.
    Find a user using the keywords if no other entry type
    could be determined.
    """
    return root().find(*args, **kwargs)


def find_user(*args, **kwargs):
    """Find a user by name or other properties
    from the cached root entry
    """
    return root().find_user(*args, **kwargs)


def search(*args, **kwargs):
    """Search from the cached root entry"""
    return root().search(*args, **kwargs)


# vim: fileencoding=utf-8 ts=4 sts=4 sw=4 autoindent expandtab syntax=python:
