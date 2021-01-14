# -*- coding: utf-8 -*-
"""active_directory - a lightweight wrapper around COM support
 for Microsoft's Active Directory

Based on active_directory 0.6.7 by Tim Golden


Active Directory is Microsoft's answer to LDAP, the industry-standard
 directory service holding information about users, computers and
 other resources in a tree structure, arranged by departments or
 geographical location, and optimized for searching.

There are several ways of attaching to Active Directory. This
 module uses the Dispatchable LDAP:// objects and wraps them
 lightly in helpful Python classes which do a bit of the
 otherwise tedious plumbing. The module is quite naive, and
 has only really been developed to aid searching, but since
 you can always access the original COM object, there's nothing
 to stop you using it for any AD operations.

+ The active directory object (AD_object) will determine its
   properties and allow you to access them as instance properties.

   eg
     import active_directory
     goldent = active_directory.find_user ("goldent")
     print ad.displayName

+ Any object returned by the AD object's operations is themselves
   wrapped as AD objects so you get the same benefits.

  eg
    import active_directory
    users = active_directory.root ().child ("cn=users")
    for user in users.search ("displayName='Tim*'"):
      print user.displayName

+ To search the AD, there are two module-level general
   search functions, two module-level functions to
   find a user and computer specifically and the search
   method on each AD_object. Usage is illustrated below:

   import active_directory as ad

   for user in ad.search (
     "objectClass='User'",
     "displayName='Tim Golden' OR sAMAccountName='goldent'"
   ):
     #
     # This search returns an AD_object
     #
     print user

   query = \"""
     SELECT Name, displayName
     FROM 'LDAP://cn=users,DC=gb,DC=vo,DC=local'
     WHERE displayName = 'John*'
   \"""
   for user in ad.search_ex (query):
     #
     # This search returns an ADO_object, which
     #  is faster but doesn't give the convenience
     #  of the AD methods etc.
     #
     print user

   print ad.find_user ("goldent")

   print ad.find_computer ("vogbp200")

   users = ad.root ().child ("cn=users")
   for u in users.search ("displayName='Tim*'"):
     print u

+ Typical usage will be:

import active_directory

for computer in active_directory.search ("objectClass='computer'"):
  print computer.displayName

(c) Tim Golden <active-directory@timgolden.me.uk> October 2004
Licensed under the (GPL-compatible) MIT License:
http://www.opensource.org/licenses/mit-license.php

Many thanks, obviously to Mark Hammond for creating
 the pywin32 extensions.
"""


import datetime
import socket
import sys

import win32api
import win32security

from win32com.client import Dispatch, GetObject


#
# Code contributed by Stian Søiland <stian@soiland.no>
#
def i32(big_number):
    """Converts an integer to a signed 32 bit integer.
    
    Python  will convert numbers >= 0x80000000 to large numbers
    instead of negative ints. This is not what we want for
    typical win32 constants.
    
    Usage:
        >>> i32(0x80005000)
        -2147363168
    """
    # x > 0x80000000 should be negative, such that:
    # i32(0x80000000) -> -2147483648
    # i32(0x80000001) -> -2147483647     etc.
    return (big_number & 0x80000000 and -2 * 0x40000000 or 0) \
        + int(big_number & 0x7fffffff)


class Signed32BitMapping():

    """Mapping of names to signed 32-bit integer numbers
    supporting lookups in each direction
    """

    def __init__ (self, **kwargs):
        """Initialize the internal mappings
        from the keyword arguments
        """
        self._name_map = {}
        self._number_map = {}
        for name, number in kwargs.items():
            signed_number = i32(number)
            self._name_map[name] = signed_number
            self._number_map[signed_number] = name

    def __getitem__(self, item):
        """Get number by name or name by number"""
        try:
            return self._name_map[item]
        except KeyError:
            return self._number_map[i32(item)]
        #

    def item_names(self):
        """(name, number) items"""
        return self._name_map.items()

    def item_numbers(self):
        """(number, name) items"""
        return self._number_map.items()


GROUP_TYPES = Signed32BitMapping(
    GLOBAL_GROUP=0x00000002,
    DOMAIN_LOCAL_GROUP=0x00000004,
    LOCAL_GROUP=0x00000004,
    UNIVERSAL_GROUP=0x00000008,
    SECURITY_ENABLED=0x80000000,
)

AUTHENTICATION_TYPES = Signed32BitMapping(
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

SAM_ACCOUNT_TYPES = Signed32BitMapping(
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

USER_ACCOUNT_CONTROL = Signed32BitMapping(
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

ENUMS = {
    "GROUP_TYPES" : GROUP_TYPES,
    "AUTHENTICATION_TYPES" : AUTHENTICATION_TYPES,
    "SAM_ACCOUNT_TYPES" : SAM_ACCOUNT_TYPES,
    "USER_ACCOUNT_CONTROL" : USER_ACCOUNT_CONTROL
}


def _bypass_set(obj, attribute, value):
    """Helper function to add an attribute directly into the instance
    dictionary, bypassing possible __getattr__ calls
    """
    obj.__dict__[attribute] = value


def _and(*args):
    """Helper function to return its parameters and-ed
    together and bracketed, ready for an SQL statement, eg:

    _and ("x=1", "y=2") => "(x=1 AND y=2)"
    """
    return " AND ".join (args)


def _add_path(root_path, relative_path):
    """Add another level to an LDAP path, eg:

    _add_path ('LDAP://DC=gb,DC=vo,DC=local', "cn=Users")
      => "LDAP://cn=users,DC=gb,DC=vo,DC=local"
    """
    protocol = "LDAP://"
    if relative_path.startswith(protocol):
        return relative_path
    #
    if root_path.startswith (protocol):
        start_path = root_path[len (protocol):]
    else:
        start_path = root_path
    #
    return protocol + relative_path + "," + start_path


#
# Global cached ADO Connection object
#

_connection = None

def connection():
    """Open a new connection or return the existing one"""
    global _connection
    if _connection is None:
        _connection = Dispatch("ADODB.Connection")
        _connection.Provider = "ADsDSOObject"
        _connection.Open("Active Directory Provider")
    return _connection


class ADORecord():

    """Simple wrapper around an ADO result set"""

    def __init__ (self, record):
        self.record = record
        self.fields = {}
        for field_number in range(record.Fields.Count):
            field = record.Fields.Item(field_number)
            self.fields[field.Name] = field
        #

    def __getattr__ (self, name):
        """Allow access to field names by name
        rather than by Item(...)
        """
        try:
            return self.fields[name]
        except KeyError:
            raise AttributeError from KeyError
        #

    def __str__ (self):
        """Return a readable presentation of the entire record"""
        readable=[repr(self), "{"]
        for name, item in self.fields.items ():
            readable.append ("  %s = %s" % (name, item))
        readable.append ("}")
        return "\n".join (readable)


def simple_query(query_string, **command_properties):
    """Auxiliary function to serve as a quick-and-dirty
    wrapper round an ADO query
    """
    command = Dispatch("ADODB.Command")
    command.ActiveConnection = connection ()
    #
    # Add any client-specified ADO command properties.
    # NB underscores in the keyword are replaced by spaces.
    #
    # Examples:
    #   "Cache_results" = False => Don't cache large result sets
    #   "Page_size" = 500 => Return batches of this size
    #   "Time Limit" = 30 => How many seconds should the search continue
    #
    for key, value in command_properties.items():
        command.Properties(key.replace("_", " ")).Value = value
    #
    command.CommandText = query_string
    recordset = command.Execute()[0]
    while not recordset.EOF:
        yield ADORecord(recordset)
        recordset.MoveNext()
    #


BASE_TIME = datetime.datetime (1601, 1, 1)


def convert_to_object(item):
    """..."""
    if item is None:
        return None
    #
    return AD_object(item)


def convert_to_objects(items):
    """..."""
    if items is None:
        return []
    #
    if not isinstance (items, (tuple, list)):
        items = [items]
    #
    return [AD_object(item) for item in items]


def convert_to_datetime(ad_time):
    """..."""
    if ad_time is None:
        return None
    #
    high, low = i32(ad_time.HighPart), i32(ad_time.LowPart)
    ns100 = (high << 32) + low
    delta = datetime.timedelta(microseconds=ns100 / 10)
    return BASE_TIME + delta


def convert_to_sid (item):
    """..."""
    if item is None:
        return None
    #
    return win32security.SID(item)


def convert_to_guid(item):
    """..."""
    if item is None:
        return None
    #
    guid = convert_to_hex(item)
    return "{%s-%s-%s-%s-%s}" % (
        guid[:8], guid[8:12], guid[12:16], guid[16:20], guid[20:])


def convert_to_hex(item):
    """..."""
    if item is None:
        return None
    #
    return "".join (["%x" % ord(i) for i in item])


def convert_to_enum(name):
    """..."""
    def _convert_to_enum(item):
        """..."""
        if item is None:
            return None
        #
        return ENUMS[name][item]
    #
    return _convert_to_enum


def convert_to_flags(enum_name):
    """..."""
    def _convert_to_flags(item):
        """..."""
        if item is None:
            return None
        #
        signed_number = i32(item)
        enum = ENUMS[enum_name]
        return set(
            name for (bitmask, name) in enum.item_numbers ()
            if signed_number & bitmask)
    #
    return _convert_to_flags


class _AD_root():

    """..."""

    def __init__ (self, obj):
        """..."""
        _bypass_set(self, "com_object", obj)
        _bypass_set(self, "properties", {})
        for item_number in range(obj.PropertyCount):
            current_property = obj.Item(item_number)
            self.properties[current_property.Name] = current_property.Value
        #


class _AD_object(object):

    """Wrap an active-directory object for easier access
    to its properties and children. May be instantiated
    either directly from a COM object or from an ADs Path, eg:

    import active_directory
    users = AD_object (path="LDAP://cn=Users,DC=gb,DC=vo,DC=local")
    """

    def __init__ (self, obj):
        """Be careful here with attribute assignment;
        __setattr__ & __getattr__ will fall over
        each other if you aren't.
        """
        _bypass_set(self, "com_object", obj)
        schema = GetObject(obj.Schema)
        _bypass_set(
            self,
            "properties",
            schema.MandatoryProperties + schema.OptionalProperties)
        _bypass_set(self, "is_container", schema.Container)
        self._property_map = dict(
            objectGUID=convert_to_guid,
            uSNChanged=convert_to_datetime,
            uSNCreated=convert_to_datetime,
            replicationSignature=convert_to_hex,
            Parent=convert_to_object,
            wellKnownObjects=convert_to_objects,
        )
        self._delegate_map = dict()

    def __getitem__ (self, key):
        """..."""
        return getattr (self, key)

    def __getattr__ (self, name):
        """Allow access to object's properties as though normal
        Python instance properties. Some properties are accessed
        directly through the object, others by calling its Get
        method. Not clear why.
        """
        try:
            return self._delegate_map[name]
        except KeyError:
            ...
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
        """..."""
        setattr(self, key, value)

    def __setattr__(self, name, value):
        """Allow attribute access to the underlying object's
        fields.
        """
        if name in self.properties:
            self.com_object.Put(name, value)
            self.com_object.SetInfo()
        else:
            _bypass_set(self, name, value)
        #

    def as_string(self):
        """..."""
        return self.path()

    def __str__(self):
        """..."""
        return self.as_string()

    def __repr__ (self):
        """..."""
        return "<%s: %s>" % (self.__class__.__name__, self.as_string())

    def __eq__ (self, other):
        """..."""
        return self.com_object.Guid == other.com_object.Guid

    class AD_iterator:
    
        """ Inner class for wrapping iterated objects
        (This class and the __iter__ method supplied by
        Stian Søiland <stian@soiland.no>)
        """
        
        def __init__(self, com_object):
            """..."""
            self._iter = iter(com_object)

        def __iter__(self):
            """..."""
            return self

        def next(self):
            """..."""
            return AD_object(self._iter.next())

    def __iter__(self):
        """..."""
        return self.AD_iterator(self.com_object)
    
    def walk(self):
        """Yield (container, subcontainers, items) tuples
        for the container and all subcontainers
        """
        this_subcontainers = []
        this_items = []
        for current_child in list(self):
            if current_child.is_container:
                this_subcontainers.append(current_child)
            else:
                this_items.append(current_child)
            #
        #
        yield self, this_subcontainers, this_items
        for subcontainer in this_subcontainers:
            for walk_item in subcontainer.walk():
                yield walk_item
            #
        #

    def dump (self, output_file=sys.stdout):
        """dump a representation of self to output_file"""
        output_file.write (self.as_string () + "\n")
        output_file.write ("{\n")
        for name in self.properties:
            try:
                value = getattr(self, name)
            except AttributeError:
                value = "Unable to get value"
            #
            if value:
                try:
                    output_file.write("  %s => %s\n" % (name, value))
                except UnicodeEncodeError:
                    output_file.write("  %s => %s\n" % (name, repr (value)))
                #
            #
        #
        output_file.write ("}\n")

    def set(self, **kwargs):
        """Set a number of values at one time. Should be
        a little more efficient than assigning properties
        one after another, eg:

        import active_directory
        user = active_directory.find_user("goldent")
        user.set(displayName = "Tim Golden", description="SQL Developer")
        """
        for key, value in kwargs.items():
            self.com_object.Put(key, value)
        #
        self.com_object.SetInfo()

    def path(self):
        """..."""
        return self.com_object.ADsPath

    def parent(self):
        """Find this object's parent"""
        return AD_object(path=self.com_object.Parent)

    def child(self, relative_path):
        """Return the relative child of this object. The relative_path
        is inserted into this object's AD path to make a coherent AD
        path for a child object, eg:

        import active_directory
        root = active_directory.root ()
        users = root.child("cn=Users")
        """
        return AD_object(path=_add_path(self.path(), relative_path))

    def __find_first(self, *args, **kwargs):
        """Return the first item found by self.search"""
        for item in self.search(*args, **kwargs):
            return item
        #

    def find_user(self, name=None):
        """..."""
        name = name or win32api.GetUserName()
        return self.__find_first(
            ' OR '.join(
                "{0}='{1}'".format(item_category, name)
                for item_category in (
                    'sAMAccountName', 'displayName', 'cn')),
            objectCategory='Person',
            objectClass='User')

    def find_computer(self, name=None):
        """..."""
        name = name or socket.gethostname()
        return self.__find_first(objectCategory='Computer', cn=name)

    def find_group(self, name):
        """..."""
        return self.__find_first(objectCategory='group', cn=name)
      
    def find_ou(self, name):
        """..."""
        return self.__find_first(objectClass="organizationalUnit", ou=name)
      
    def find_public_folder (self, name):
        """..."""
        return self.__find_first(objectClass="publicFolder", displayName=name)

    def search (self, *args, **kwargs):
        """Build an SQL statemenr and execute a simple query
        with it
        """
        sql_statement = [
            "SELECT *",
            "FROM '{0}'".format(self.path())]
        where_clauses = list(args) + [
            "%s='%s'" % (key, value) for (key, value) in kwargs.items()]
        if where_clauses:
            sql_statement.append(" AND ".join(where_clauses))
        #
        for result in simple_query("\n".join(sql_statement), Page_size=50):
            yield AD_object(result.ADsPath.Value)
        #


class _AD_user(_AD_object):

    """..."""

    def __init__(self, *args, **kwargs):
        """..."""
        super().__init__(*args, **kwargs)
        self._property_map.update(dict(
            pwdLastSet=convert_to_datetime,
            memberOf=convert_to_objects,
            objectSid=convert_to_sid,
            accountExpires=convert_to_datetime,
            badPasswordTime=convert_to_datetime,
            lastLogoff=convert_to_datetime,
            lastLogon=convert_to_datetime,
            lastLogonTimestamp=convert_to_datetime,
            lockoutTime=convert_to_datetime,
            msExchMailboxGuid=convert_to_guid,
            publicDelegates=convert_to_objects,
            publicDelegatesBL=convert_to_objects,
            sAMAccountType=convert_to_enum("SAM_ACCOUNT_TYPES"),
            userAccountControl=convert_to_flags("USER_ACCOUNT_CONTROL"),
        ))


class _AD_computer(_AD_object):

    """..."""

    def __init__(self, *args, **kwargs):
        """..."""
        super().__init__(*args, **kwargs)
        self._property_map.update(dict(
            objectSid=convert_to_sid,
            accountExpires=convert_to_datetime,
            badPasswordTime=convert_to_datetime,
            lastLogoff=convert_to_datetime,
            lastLogon=convert_to_datetime,
            lastLogonTimestamp=convert_to_datetime,
            publicDelegates=convert_to_objects,
            publicDelegatesBL=convert_to_objects,
            pwdLastSet=convert_to_datetime,
            sAMAccountType=convert_to_enum("SAM_ACCOUNT_TYPES"),
            userAccountControl=convert_to_flags("USER_ACCOUNT_CONTROL"),
        ))


class _AD_group(_AD_object):

    """..."""

    def __init__(self, *args, **kwargs):
        """..."""
        super().__init__(*args, **kwargs)
        self._property_map.update(dict(
            groupType=convert_to_flags("GROUP_TYPES"),
            objectSid=convert_to_sid,
            member=convert_to_objects,
            memberOf=convert_to_objects,
            sAMAccountType=convert_to_enum("SAM_ACCOUNT_TYPES"),
        ))

    def walk (self):
        """..."""
        members = self.member or []
        groups = []
        users = []
        for single_member in members:
            if single_member.Class == 'group':
                groups.append(single_member)
            elif single_member.Class == 'user':
                users.append(single_member)
            #
        #
        yield (self, groups, users)
        for child_group in groups:
            for result in child_group.walk ():
                yield result
            #
        #


class _AD_organisational_unit(_AD_object):

    """..."""

    ...


class _AD_domain_dns (_AD_object):

    """..."""

    def __init__(self, *args, **kwargs):
        """..."""
        super().__init__(*args, **kwargs)
        self._property_map.update(dict(
            creationTime=convert_to_datetime,
            dSASignature=convert_to_hex,
            forceLogoff=convert_to_datetime,
            fSMORoleOwner=convert_to_object,
            lockoutDuration=convert_to_datetime,
            lockoutObservationWindow=convert_to_datetime,
            masteredBy=convert_to_objects,
            maxPwdAge=convert_to_datetime,
            minPwdAge=convert_to_datetime,
            modifiedCount=convert_to_datetime,
            modifiedCountAtLastProm=convert_to_datetime,
            objectSid=convert_to_sid,
            replUpToDateVector=convert_to_hex,
            repsFrom=convert_to_hex,
            repsTo=convert_to_hex,
            subRefs=convert_to_objects,
            wellKnownObjects=convert_to_objects,
        ))
        self._property_map['msDs-masteredBy'] = convert_to_objects
    
class _AD_public_folder (_AD_object):

    """..."""
    
    ...


_CLASS_MAP = {
    "user" : _AD_user,
    "computer" : _AD_computer,
    "group" : _AD_group,
    "organizationalUnit" : _AD_organisational_unit,
    "domainDNS" : _AD_domain_dns,
    "publicFolder" : _AD_public_folder,
}

_CACHE = {}


def cached_AD_object (path, obj):
    """..."""
    try:
        return _CACHE[path]
    except KeyError:
        classed_obj = _CLASS_MAP.get(obj.Class, _AD_object)(obj)
        return _CACHE.setdefault(path, classed_obj)
    #


def AD_object (obj_or_path=None, path=""):
    """Factory function for suitably-classed Active Directory
    objects from an incoming path or object. NB The interface
    is now  intended to be:

    AD_object (obj_or_path)

    but for historical reasons will continue to support:

    AD_object (obj=None, path="")

    @param obj_or_path Either an COM AD object or the path to one. If
    the path doesn't start with "LDAP://" this will be prepended.

    @return An _AD_object or a subclass proxying for the AD object
    """
    if path and not obj_or_path:
        obj_or_path = path
    try:
        if isinstance (obj_or_path, str):
            if not obj_or_path.upper().startswith ("LDAP://"):
                obj_or_path = "LDAP://" + obj_or_path
            #
            return cached_AD_object(obj_or_path, GetObject(obj_or_path))
        #
        return cached_AD_object(obj_or_path.ADsPath, obj_or_path)
    except Exception as error:
        raise ValueError(
            "Problem with path or object %s" % obj_or_path) from error
    #


def AD(server=None):
    """..."""
    default_naming_context = _root(server).Get("defaultNamingContext")
    return AD_object(GetObject("LDAP://%s" % default_naming_context))


def _root (server=None):
    """..."""
    if server:
        return GetObject("LDAP://%s/rootDSE" % server)
    else:
        return GetObject("LDAP://rootDSE")


def find_user(name=None):
    """..."""
    return root().find_user(name)


def find_computer(name=None):
    """..."""
    return root().find_computer(name)


def find_group(name):
    """..."""
    return root().find_group(name)


def find_ou(name):
    """..."""
    return root().find_ou(name)


def find_public_folder(name):
    """..."""
    return root().find_public_folder(name)


#
# root returns a cached object referring to the
#  root of the logged-on active directory tree.
#

_ad = None


def root ():
    """..."""
    global _ad
    if _ad is None:
        _ad = AD()
    #
    return _ad

def search(*args, **kwargs):
    """..."""
    return root().search(*args, **kwargs)


def search_ex(query_string=""):
    """Search the Active Directory by specifying a complete
    query string. NB The results will *not* be AD_objects
    but rather ADO_objects which are queried for their fields, eg:


     import active_directory
     for user in active_directory.search_ex (\"""
       SELECT displayName
       FROM 'LDAP://DC=gb,DC=vo,DC=local'
       WHERE objectCategory = 'Person'
     \"""):
       print user.displayName
    """
    for result in simple_query(query_string, Page_size=50):
        yield result


# vim: fileencoding=utf-8 ts=4 sts=4 sw=4 autoindent expandtab syntax=python:
