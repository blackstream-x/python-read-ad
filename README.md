# read_ad

COM-based readonly access for Active Directory in Python

_forked off active_directory.py v0.6.7 by Tim Golden_

In contrast to the original, this module provides read access only.
For full-featured Active Directory access, please refer to the latest
implementation of the original (https://github.com/tjguk/active_directory).

This module requires Python 3.x (tested with 3.6 and above)
and the pywin32 module (https://pypi.org/project/pywin32/)

## Module contents

### Constants / Global Variables

#### Handling Active Directory times ####

##### BASE_TIME

> A datetime.datetime instance with value 1600-01-01, the base date of Active Directory times.

##### TIME_NEVER_HIGH_PART

> ```0x7fffffff```

##### TIME_NEVER_KEYWORD

> ```'<never>'``` as a textual replacement for an Active Directory "never" time.

#### Constants for ADO/COM access ###

##### ADO_COMMAND

> ```'ADODB.Command'```

##### ADO_CONNECTION

> ```'ADODB.Connection'```

##### CONNECTION_PROVIDER

> ```'ADsDSOObject'```

##### CONNECTION_TARGET

> ```'Active Directory Provider'```

#### Internal cache keywords ####

##### CACHE_KEY_CONNECTION

> ```'_Connection_'``` as the key for caching the connection object.

##### CACHE_KEY_ROOT

> ```'_ActiveDirectoryRoot_'``` as the key for caching the Active Directory root URL.

#### Mappings ####

##### GLOBAL_CACHE

> A global cache of **LdapEntry** objects mapped to LDAP Urls,
> plus the connection object and the Active Directory root URL.

##### GROUP_TYPES

> A **FlagsMapping()** with Active Directory group type bitmasks;
> Values are taken from upstream (see https://github.com/tjguk/active_directory/blob/master/active_directory.py#L164)

##### AUTHENTICATION_TYPES

> A **FlagsMapping()** with Active Directory authentication type bitmasks;
> Values are taken from upstream (see https://github.com/tjguk/active_directory/blob/master/active_directory.py#L172)

##### SAM_ACCOUNT_TYPES

> A **UnsignedIntegerMapping()** with Active Directory account type magic numbers;
> Values are taken from upstream (see https://github.com/tjguk/active_directory/blob/master/active_directory.py#L187)

##### USER_ACCOUNT_CONTROL

> A **FlagsMapping()** with Active Directory user account state bitmasks;
> Values are taken from upstream (see https://github.com/tjguk/active_directory/blob/master/active_directory.py#L202)

##### SEARCH_FILTERS

> A dict of **SearchFilter** instances mapped to keywords for searching groups, computers, public folders, organizational units or users.

### Classes

#### UnsignedIntegerMapping(_\*\*kwargs_)

A Mapping of unsigned integers to names with reverse lookup functionality.
Member access usng a name returns the associated number und vice versa.

##### .get_name(_number_)

> Explicitly returns the name associated with the given number.


#### FlagsMapping(_\*\*kwargs_)

An **UnsignedIntegerMapping** subclass for bitmasks mapped to flag names

##### .get_flag_names(_number_)

> Returns a set of all flag names for the bitmasks matching the given number.



_(tba: PathComponent, RecordSet)_

#### LdapPath(_\*parts_)

Instances of this class represent an LDAP path.
They are initialized using the provided parts, which can be strings or **PathComponent** instances.

##### .components

> The compoents of the path (a tuple of **PathComponent** instances)

##### .rdn

> The relative distinguished name of the LPAP path (the **.value** of the first component)

##### .url

> The LDAP URL of the path (the distinguished name prefixed with ```'LDAP://'```)

##### .from_string(string)

> _Constructor (class)method_, returns an **LdapPath** instance built from the provided _string_ splitted by non-escaped commas (```,```).

#### SearchFilter(_primary\_key\_name, \*\*fixed_parameters_)

Instances of this class hold a primary key name and a mapping of fixed parameters for an LDAP search.

##### .where_clause(_\*args, \*\*kwargs_)

> Return a ```WHERE``` clause for an SQL-like LDAP query string,
> built from the provided positional and keyword arguments,
> all concatenated unsing ```AND```.  
> The stored fixed parameters override the provided keyword arguments.
> If a _\_primary\_key\__ keyword was provided, its value is
> built into the clause using the stored primary key name.

##### .execute_query(_ldap\_path, \*args, \*\*kwargs_)

> Return an interator from the result of an LDAP query
> (using the **RecordSet.query()** class method)
> starting at the URL of the provided **LdapPath** instance,
> using SQL syntax with the WHERE clause genarated by **.where_clause()** method.


#### LdapEntry(_com\_object_)

Stores a subset of an LDAP entry's properties.
The stored properties can be accessed via item access using \[_property\_name_\]
or (in the case of suitable property names) via attribute access using ._property\_name_

##### .empty\_properties

> A sorted list of the names of all properties having the value None.

##### .parent

> An **LdapEntry** subclass instance of the current entry's parent

##### .path

> An **LdapPath** instance from the _ADsPath_ property

##### .items()

> Returns an iterator over the property names and their values as dict items
> (if the value is not None).

##### .print_dump()

> Prints a case-sensitive (i.e. uppercase before lowercase) alphabetically sorted dump
> of non-empty properties.

##### .child(_single\_path\_component_)

> Returns an **LdapEntry** subclass instance for a relative child of this instance.
> Its path is determined by prepending the _single\_path\_component_ to this instance's path. 


#### User(_com\_object_)

**LdapEntry** subclass for Active Directory users

##### .account_disabled

> ```True``` if the account is disabled, ```False``` if it is active.


#### Group(_com\_object_)

**LdapEntry** subclass for Active Directory groups

##### .walk()

> Returns an iterator over tuples, each consisting of: _1._ the current **Group** instance,
> _2._ a list of member **Group** instances and _3._ a list of member **User** instances.


#### Computer(_com\_object_)

**LdapEntry** subclass for Active Directory computers


#### OrganizationalUnit(_com\_object_)

**LdapEntry** subclass for Active Directory organizational units, supporting searches 

##### .find(_\*args, \*\*kwargs_)

> Returns an **LdapEntry** subclass instance made from the first found LDAP entry
> from an LDAP search starting at this instance's path,
> or None if nothing was found. 

##### .find_user(_\*args, \*\*kwargs_)

> Returns a **User** instance made from the first found LDAP entry
> from an LDAP search starting at this instance's path,
> or None if nothing was found. 

##### .search(_\*args, active=None, search\_filter=None, \*\*kwargs_)

> Returns an iterator over all found LDAP paths
> from an LDAP search starting at this instance's path.

> If _active_ is set to ```True``` or ```False``` explicitly, the method returns only
> the paths of active (or deactivated) matching entries. 

> If _search_filter_ is set to a SearchFilter instance,
> this method uses that instance to search the Active Directory.
> Else, it determines which SearchFilter instance to use
> from the **SEARCH_FILTERS** mapping.


#### DomainDNS(_com\_object_)

**OrganizationalUnit** subclass for the Active Directory domain DNS


#### PublicFolder(_com\_object_)

**LdapEntry** subclass for Active Directory public folders


### Public interface functions

#### produce_entry(_ldap\_path, lazy=True_)

> **LdapEntry** subclass factory function.

> Determines the suitable **LdapEntry** subclass from the
> COM object found at the given LDAP path.
> Generates an instance of this class from the COM object,
> stores it in **GLOBAL_CACHE** (associated to the LDAP path URL),
> and returns the Instance.

> if _lazy_ is set to ```True``` (the default), this function returns
> the suitable cached entry if it exists, avoiding expensive lookups
> and network traffic.

#### root(_server=None_)

> Returns the (cached) **DomainDNS** instance referring to the
> root of the logged-on Active Directory tree.

#### find(_\*args, \*\*kwargs_)

> Returns an **LdapEntry** subclass instance made from the first found LDAP entry
> from an LDAP search starting at the active Directory root's path,
> or None if nothing was found.

#### find_user(_\*args, \*\*kwargs_)

> Returns a **User** instance made from the first found LDAP entry
> from an LDAP search starting at the active Directory root's path,
> or None if nothing was found.

#### search(_\*args, \*\*kwargs_)

> Returns an iterator over all found LDAP paths
> from an LDAP search starting at the active Directory root's path.

#### search_explicit(_query\_string_)

> Returns an iterator over **RecordSet** instances from a query using
> the given _query\_string_

## Examples

```python
import read_ad

# read_ad.root() returns the cached Active Directory root entry

# find your own user in active directory
import getpass
my_user = read_ad.find_user(getpass.getuser())

```
