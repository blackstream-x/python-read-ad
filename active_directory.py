# -*- coding: utf-8 -*-
"""

active_directory

a lightweight wrapper around COM support for Active Directory

Based on original version 0.6.7 by Tim Golden
(see <http://timgolden.me.uk/python/active_directory.html>)
with a few cherry-picks from the current implementation
(<https://github.com/tjguk/active_directory/blob/master/active_directory.py>)

Rewrite for Python3 with minimal external dependencies
(i.e. win32com.client and win32security)
by Rainer Schwarzbach, 2021-01-19

License: MIT

"""


import datetime
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

LDAP_URL_PREFIX = 'LDAP://'

_CACHE = {}


#
# Helper functions
#


def connection():
    """Open a new connection or return the cached existing one"""
    try:
        return _CACHE['connection']
    except KeyError:
        new_connection = win32com.client.Dispatch('ADODB.Connection')
        new_connection.Provider = 'ADsDSOObject'
        new_connection.Open('Active Directory Provider')
        return _CACHE.setdefault('connection', new_connection)
    #


def ldap_url(ldap_path):
    """Return the path prefixed with LDAP_URL_PREFIX"""
    if ldap_path.upper().startswith(LDAP_URL_PREFIX):
        return ldap_path
    #
    return '%s%s' % (LDAP_URL_PREFIX, ldap_path)


def signed_to_unsigned(signed):
    """Convert a signed integer to an unsigned one,
    taken from the current upstream implementation
    <https://github.com/tjguk/active_directory/
     blob/master/active_directory.py>
    """
    return struct.unpack('L', struct.pack('l', signed))[0]


def _add_path(root_path, relative_path):
    """Add another level to an LDAP path, eg:

    _add_path('LDAP://DC=gb,DC=vo,DC=local', "cn=Users")
      => "LDAP://cn=users,DC=gb,DC=vo,DC=local"
    """
    if relative_path.startswith(LDAP_URL_PREFIX):
        return relative_path
    #
    if root_path.startswith(LDAP_URL_PREFIX):
        start_path = root_path[len(LDAP_URL_PREFIX):]
    else:
        start_path = root_path
    #
    return '%s%s,%s' % (LDAP_URL_PREFIX, relative_path, start_path)


# Conversion of Active Directory Objects' properties


def convert_to_datetime(ad_time):
    """Return a datetime from active directory.

    from <https://ldapwiki.com/wiki/Microsoft%20TIME>
    'Microsoft TIME is a mess.'

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


def convert_to_sid(item):
    """Return a PySID from binary data"""
    if item is None:
        return None
    #
    return win32security.SID(bytes(item))


def convert_to_guid(item):
    """Return a GUID from an Active Directory object's property"""
    if item is None:
        return None
    #
    guid = convert_to_hex(item)
    return '{%s-%s-%s-%s-%s}' % (
        guid[:8], guid[8:12], guid[12:16], guid[16:20], guid[20:])


def convert_to_hex(item):
    """Retirn a hexadecimal representation of binary data"""
    if item is None:
        return None
    #
    return ''.join('%02x' % (char & 0xff) for char in bytes(item))


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
        self._name_map = {}
        self._number_map = {}
        for name, number in kwargs.items():
            self._name_map[name] = number
            self._number_map[number] = name

    def __getitem__(self, item):
        """Get number by name or name by number"""
        try:
            return self._name_map[item]
        except KeyError:
            return self._number_map[signed_to_unsigned(item)]
        #

    def item_names(self):
        """(name, number) items"""
        return self._name_map.items()

    def item_numbers(self):
        """(number, name) items"""
        return self._number_map.items()

    def get(self, item):
        """Return the matching name"""
        if item is None:
            return None
        #
        return self[item]


class FlagsMapping(UnsignedIntegerMapping):

    """Return a set of flag names when calling
    self.get_flag_names(number)
    """

    def get_flag_names(self, number):
        """Return a set of flag names"""
        if number is None:
            return None
        #
        unsigned_number = signed_to_unsigned(number)
        return set(
            name for (bitmask, name) in self.item_numbers()
            if unsigned_number & bitmask)


#
# Flag and value mapping constants
#


GROUP_TYPES = FlagsMapping(
    GLOBAL_GROUP=0x00000002,
    DOMAIN_LOCAL_GROUP=0x00000004,
    LOCAL_GROUP=0x00000004,
    UNIVERSAL_GROUP=0x00000008,
    SECURITY_ENABLED=0x80000000,
)

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
    AUTH_RESERVED=0x80000000,
)

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
    SAM_ACCOUNT_TYPE_MAX=0x7fffffff,
)

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
    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION=0x01000000,
)


class ADORecord():

    """Simple wrapper around an ADO result set"""

    def __init__(self, record):
        """Store the fields of the record by name"""
        #self.record = record
        self.fields = {}
        for field_number in range(record.Fields.Count):
            field = record.Fields.Item(field_number)
            self.fields[field.Name] = field.Value
        #

    def __getattr__(self, name):
        """Allow access to field names by name
        rather than by Item(...)
        """
        try:
            return self.fields[name]
        except KeyError:
            raise AttributeError from KeyError
        #

    def dump_fields(self):
        """Yield all field names and values"""
        for name, item in self.fields.items():
            yield '%s=%r' % (name, item)
        #

    def __str__(self):
        """Return a readable presentation of the entire record"""
        output = ['{']
        output.extend('  %s' % field for field in self.dump_fields())
        output.append('}')
        return '\n'.join(output)

    def __repr__(self):
        """Return a readable presentation of the entire record"""
        output = ['<%s: ' % self.__class__.__name__]
        output.append(', '.join(self.dump_fields()))
        output.append('>')
        return ''.join(output)

    @classmethod
    def query(cls, query_string, **kwargs):
        """Yield ADORecord objects from each result of an ADO query"""
        command = win32com.client.Dispatch("ADODB.Command")
        command.ActiveConnection = connection()
        #
        # Add additional ADO command properties
        # specified as keyword arguments.
        # NB underscores in the keyword are replaced by spaces.
        #
        # Examples:
        #   Cache_results=False => Don't cache large result sets
        #   Page_size=500 => Return batches of this size
        #   Time_Limit=30 => How many seconds should the search continue
        for key, value in kwargs.items():
            command.Properties(key.replace('_', ' ')).Value = value
        #
        command.CommandText = query_string
        recordset = command.Execute()[0]
        while not recordset.EOF:
            yield cls(recordset)
            recordset.MoveNext()
        #


class DistinguishedName():

    """Simple access to the parts of a distinguished name,
    instantiated using either an ActiveDirectoryObject
    or a string.
    """

    prx_comma = re.compile(r'(?<!\\),')
    prx_equals = re.compile(r'(?<!\\)=')

    def __init__(self, object_or_dn):
        """Keep a dict of name parts"""
        try:
            distinguished_name = object_or_dn.distinguishedName
        except AttributeError:
            if not isinstance(object_or_dn, str):
                raise ValueError(
                    '%s must be instantiated using an ActiveDirectoryObject'
                    ' or a string.' % self.__class__.__name__)
            #
            distinguished_name = object_or_dn
        #
        self.__components = {}
        for name_part in self.prx_comma.split(distinguished_name):
            try:
                key, value = self.prx_equals.split(name_part)
            except ValueError as error:
                raise ValueError(
                    'Not a valid DN: %s' & distinguished_name) from error
            #
            key = key.strip().lower()
            self.__components.setdefault(key, []).append(value)
        #

    @property
    def common_name(self):
        """Return the first (!) cn attribute only"""
        return self.cn[0]

    def all_parts(self):
        """Yield all parts"""
        for (key, values) in self.__components.items():
            for single_value in values:
                yield '%s=%s' % (key, single_value)
            #
        #

    def __getitem__(self, key):
        """Return the values for the given key"""
        return self.__components[key]

    def __getattr__(self, key):
        """Return the values for the given key (case insensitive)"""
        try:
            return self[key.lower()]
        except KeyError:
            raise AttributeError('No %r in %r' % (key, self))
        #

    def __str__(self):
        """Return the distinguished name"""
        return ','.join(self.all_parts())

    def __hash__(self):
        """Return a hash over the distinguished name"""
        return hash(str(self))

    def __repr__(self):
        """Return the distinguished name prefixed with the
        class name
        """
        return '%s: %s' % (self.__class__.__name__, self)


#
# Active Directory objects
#


class ActiveDirectoryCbject():

    """Wrap an active directory object for easier access
    to its properties and children. May be instantiated
    either directly from a COM object or from an ADs Path, eg:

    import active_directory
    users = active_directory.ad_object_factory(
        "LDAP://cn=Users,DC=gb,DC=vo,DC=local")
    """

    additional_conversions = ()
    user_search_fields = ('sAMAccountName', 'displayName', 'cn')

    def __init__(self, com_object):
        """Be careful here with attribute assignment;
        __setattr__ & __getattr__ will fall over
        each other if you aren't.
        """
        schema = win32com.client.GetObject(com_object.Schema)
        self.com_object = com_object
        self.properties = \
            schema.MandatoryProperties + schema.OptionalProperties
        self.is_container = schema.Container
        self._property_map = dict(
            objectGUID=convert_to_guid,
            uSNChanged=convert_to_datetime,
            uSNCreated=convert_to_datetime,
            replicationSignature=convert_to_hex)
        self._property_map.update(self.additional_conversions)
        self._delegate_map = dict()

    def __getitem__(self, key):
        """Item access (here: read) delegated to attribute access"""
        return getattr(self, key)

    def __getattr__(self, name):
        """Allow access to the com object's properties as through
        normal Python instance properties.
        Some properties are accessed directly through the object,
        others by calling its Get method. Not clear why.
        """
        try:
            return self._delegate_map[name]
        except KeyError:
            pass
        #
        try:
            attr = getattr(self.com_object, name)
        except AttributeError:
            try:
                attr = self.com_object.Get(name)
            except:
                raise AttributeError
        #
        try:
            converter = self._property_map[name]
        except KeyError:
            return self._delegate_map.setdefault(name, attr)
        #
        return self._delegate_map.setdefault(name, converter(attr))

    def __setitem__(self, key, value):
        """Item access (here: write) delegated to attribute access"""
        setattr(self, key, value)

    def __setattr__(self, name, value):
        """Allow attribute access to the underlying object's
        fields.
        """
        if name in self.__dict__.get('properties', ()):
            self.com_object.Put(name, value)
            self.com_object.SetInfo()
        else:
            object.__setattr__(self, name, value)
        #

    def __str__(self):
        """Return the path"""
        return self.path()

    def __repr__(self):
        """Return a representation with the class name
        and the path
        """
        return "<%s: %s>" % (self.__class__.__name__, self.path())

    def __eq__(self, other):
        """Compare the COM objects' GUIDs"""
        return self.com_object.GUID == other.com_object.GUID

    def __hash__(self):
        """Identify by the COM object's GUID"""
        return self.com_object.GUID

    def __iter__(self):
        """Iterate over the com_object's contained objects
        and yield an ActiteveDirectoryObject for each one
        """
        for item in self.com_object:
            yield CachedObject.from_object(item)
        #

    def iterdump(self):
        """Yield all lines of a representation of self
        (i.e. all non-empty properties)
        """
        for name in self.properties:
            try:
                value = getattr(self, name)
            except AttributeError:
                yield '%s <not defined>' % name
                continue
            #
            if value:
                yield '%s => %r' % (name, value)
            #
        #

    def dump(self):
        """Print a representation of self"""
        print('%s:\n{' % self)
        for line in self.iterdump():
            print('  %s' % line)
        #
        print('}')

    def path(self):
        """Return the COM object's ADsPath"""
        return self.com_object.ADsPath

    def parent(self):
        """Find this object's parent"""
        return CachedObject.from_path(self.com_object.Parent)

    def child(self, relative_path):
        """Return the relative child of this object. The relative_path
        is inserted into this object's AD path to make a coherent AD
        path for a child object, eg:

        import active_directory
        root = active_directory.root()
        users = root.child("cn=Users")
        """
        return CachedObject.from_path(
            _add_path(self.path(), relative_path))

    def find_first(self, *args, **kwargs):
        """Return the first item found by self.search"""
        for found_path in self.search(*args, **kwargs):
            return CachedObject.from_path(found_path)
        #

    def find_group(self, name=None, **kwargs):
        """Find a group by name or other properties"""
        if name:
            kwargs['cn'] = name
        #
        kwargs.update(dict(objectCategory='group'))
        return self.find_first(**kwargs)

    def find_user(self, name=None, **kwargs):
        """Find a user by name or other properties"""
        find_args = []
        if name:
            find_args.append(
                ' OR '.join(
                    "%s='%s'" % (field_name, name)
                    for field_name in self.user_search_fields))
        #
        kwargs.update(
            dict(objectCategory='Person',
                 objectClass='User'))
        return self.find_first(*find_args, **kwargs)

    def find_computer(self, name):
        """Find a computer by name"""
        return self.find_first(objectCategory='Computer', cn=name)

    def find_ou(self, name):
        """Find an OU by name"""
        return self.find_first(objectClass="organizationalUnit", ou=name)

    def find_public_folder(self, name):
        """Find a public folder by name"""
        return self.find_first(objectClass="publicFolder", displayName=name)

    def __search_with_state(self, *args, **kwargs):
        """Build an SQL statement and execute a query with it.
        Yield AD result objects.
        """
        sql_statement = [
            "SELECT ADsPath, userAccountControl",
            "FROM '%s'" % self.path()]
        where_clauses = list(args) + [
            "%s='%s'" % (key, value) for (key, value) in kwargs.items()]
        if where_clauses:
            sql_statement.append("WHERE %s" % " AND ".join(where_clauses))
        #
        for result in ADORecord.query("\n".join(sql_statement), Page_size=50):
            yield result
        #

    def search(self, *args, **kwargs):
        """Yield paths for all found objects"""
        for result in self.__search_with_state(*args, **kwargs):
            yield result.ADsPath
        #

    def search_active(self, *args, **kwargs):
        """Yield paths for all active objects"""
        for result in self.__search_with_state(*args, **kwargs):
            if not (result.userAccountControl
                    & USER_ACCOUNT_CONTROL['ADS_UF_ACCOUNTDISABLE']):
                yield result.ADsPath
            #
        #

    def search_inactive(self, *args, **kwargs):
        """Yield paths for all inactive objects"""
        for result in self.__search_with_state(*args, **kwargs):
            if (
                    result.userAccountControl
                    & USER_ACCOUNT_CONTROL['ADS_UF_ACCOUNTDISABLE']):
                yield result.ADsPath
            #
        #


class Group(ActiveDirectoryCbject):

    """Active Directory group"""

    additional_conversions = dict(
        groupType=GROUP_TYPES.get_flag_names,
        objectSid=convert_to_sid,
        sAMAccountType=SAM_ACCOUNT_TYPES.get)

    def walk(self):
        """Yield a tuple of
        (self, subgroups, users) and repeat that recursively
        for each subgroup.
        """
        members = self.member or []
        if isinstance(members, str):
            members = [members]
        #
        groups = []
        users = []
        for single_path in members:
            single_member = CachedObject.from_path(single_path)
            if single_member.Class == 'group':
                groups.append(single_member)
            elif single_member.Class == 'user':
                users.append(single_member)
            #
        #
        yield (self, groups, users)
        for child_group in groups:
            for result in child_group.walk():
                yield result
            #
        #


class User(ActiveDirectoryCbject):

    """Active Directory user with an additional bool property
    (account_disabled)
    """

    additional_conversions = dict(
        pwdLastSet=convert_to_datetime,
        objectSid=convert_to_sid,
        accountExpires=convert_to_datetime,
        badPasswordTime=convert_to_datetime,
        lastLogoff=convert_to_datetime,
        lastLogon=convert_to_datetime,
        lastLogonTimestamp=convert_to_datetime,
        lockoutTime=convert_to_datetime,
        msExchMailboxGuid=convert_to_guid,
        sAMAccountType=SAM_ACCOUNT_TYPES.get,
        userAccountControl=USER_ACCOUNT_CONTROL.get_flag_names)

    @property
    def account_disabled(self):
        """Return True if the account is disabled"""
        return 'ADS_UF_ACCOUNTDISABLE' in self.userAccountControl


class Computer(ActiveDirectoryCbject):

    """Active Directory computer"""

    additional_conversions = dict(
        objectSid=convert_to_sid,
        accountExpires=convert_to_datetime,
        badPasswordTime=convert_to_datetime,
        lastLogoff=convert_to_datetime,
        lastLogon=convert_to_datetime,
        lastLogonTimestamp=convert_to_datetime,
        pwdLastSet=convert_to_datetime,
        sAMAccountType=SAM_ACCOUNT_TYPES.get,
        userAccountControl=USER_ACCOUNT_CONTROL.get_flag_names)


class OrganisationalUnit(ActiveDirectoryCbject):

    """Active Directory OU"""

    pass


class DomainDNS(ActiveDirectoryCbject):

    """Active Directory Domain DNS"""

    additional_conversions = {
        'creationTime': convert_to_datetime,
        'dSASignature': convert_to_hex,
        'forceLogoff': convert_to_datetime,
        'lockoutDuration': convert_to_datetime,
        'lockoutObservationWindow': convert_to_datetime,
        'maxPwdAge': convert_to_datetime,
        'minPwdAge': convert_to_datetime,
        'modifiedCount': convert_to_datetime,
        'modifiedCountAtLastProm': convert_to_datetime,
        'objectSid': convert_to_sid,
        'replUpToDateVector': convert_to_hex,
        'repsFrom': convert_to_hex,
        'repsTo': convert_to_hex,
    }


class PublicFolder(ActiveDirectoryCbject):

    """Active Directory public folder"""

    pass


class CachedObject():

    """ActiveDirectoryObject factory and cache

    The from_path() and from_object() methods
    cache and return an instance of ActiveDirectoryCbject
    or one of its subclasses.
    """

    class_map = {
        "user" : User,
        "computer" : Computer,
        "group" : Group,
        "organizationalUnit" : OrganisationalUnit,
        "domainDNS" : DomainDNS,
        "publicFolder" : PublicFolder,
    }
    _cache = {}

    @classmethod
    def _register_object(cls, path, com_object):
        """Cache and return a new Active Directory Object"""
        ado_class = cls.class_map.get(com_object.Class, ActiveDirectoryCbject)
        try:
            cls._cache[path] = ado_class(com_object)
        except Exception as error:
            raise ValueError(
                "Problem with object %s: %s" % (com_object, error)) from error
        #
        return cls._cache[path]

    @classmethod
    def from_path(cls, path, prefer_cached=True):
        """Return the cached object or register a new one,
        based on the path
        """
        path = ldap_url(path)
        if prefer_cached and path in cls._cache:
            return cls._cache[path]
        #
        try:
            com_object = win32com.client.GetObject(path)
        except Exception as error:
            raise ValueError(
                "Problem with path %s: %s" % (path, error)) from error
            #
        #
        return cls._register_object(path, com_object)

    @classmethod
    def from_object(cls, com_object, prefer_cached=True):
        """Return the cached object or register a new one,
        based on the COM object
        """
        path = com_object.ADsPath
        if prefer_cached and path in cls._cache:
            return cls._cache[path]
        #
        return cls._register_object(path, com_object)


#
# Module-level functions
#


def root(server=None):
    """Return a cached object referring to the
    root of the logged-on active directory tree.
    """
    try:
        return _CACHE['directory']
    except KeyError:
        root_dse_path = 'rootDSE'
        if server:
            root_dse_path = '%s/%s' % (server, root_dse_path)
        #
        ldap_root = win32com.client.GetObject(ldap_url(root_dse_path))
        default_naming_context = ldap_root.Get("defaultNamingContext")
        return _CACHE.setdefault(
            'directory',
            CachedObject.from_path(ldap_url(default_naming_context)))
    #


def find(**kwargs):
    """Find a computer, ou, or public folder by name
    from the cached root object.
    Determine the type by the keyword argument.
    Find a user using the keywords if no other object type
    could be determined.
    """
    root_object = root()
    for keyword in ('computer', 'ou', 'public_folder'):
        try:
            name = kwargs.pop(keyword)
        except KeyError:
            continue
        #
        find_method = getattr(root_object, 'find_%s' % keyword)
        return find_method(name)
    #
    return root_object.find_user(**kwargs)


def find_group(name=None, **kwargs):
    """Find a group by name or other properties
    from the cached root object
    """
    return root().find_group(name=name, **kwargs)


def find_user(name=None, **kwargs):
    """Find a user by name or other properties
    from the cached root object
    """
    return root().find_user(name=name, **kwargs)


def search(*args, **kwargs):
    """Search from the cached root object"""
    return root().search(*args, **kwargs)


def search_explicit(query_string):
    """Search the Active Directory by specifying an explicit
    query string.

    NB The results will *not* be ActiveDirectoryObjects
    but rather ADO_objects which are queried for their fields, eg:

    import active_directory
    query_string = \"""SELECT displayName
    FROM 'LDAP://DC=gb,DC=vo,DC=local'
    WHERE objectCategory = 'Person'
    \"""
    for user in active_directory.search_ex(query_string):
        print user.displayName
    """
    for result in ADORecord.query(query_string, Page_size=50):
        yield result
    #


# vim: fileencoding=utf-8 ts=4 sts=4 sw=4 autoindent expandtab syntax=python:
