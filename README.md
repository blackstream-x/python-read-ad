# python-read-ad

COM-based readonly access for Active Directory in Python 3,
_forked from Tim Golden's active\_directory.py v0.6.7_

## Module description

Installation: ```pip install read-ad```

Module name: ```read_ad```

Dependencies: Python 3.x and the pywin32 module (https://pypi.org/project/pywin32/)

Goals: minimum dependencies, maximum speed, easy usage.

In contrast to the original, this module provides read access only.
For full-featured Active Directory access, please refer to the latest
version of the original, hosted at https://github.com/tjguk/active_directory.


## Module contents

### Constants / Global Variables

#### Constants for ADO/COM access ###

##### ADO\_COMMAND

> ```'ADODB.Command'```

##### ADO\_CONNECTION

> ```'ADODB.Connection'```

##### CONNECTION\_PROVIDER

> ```'ADsDSOObject'```

##### CONNECTION\_TARGET

> ```'Active Directory Provider'```

#### Internal cache keywords ####

##### CACHE\_KEY\_CONNECTION

> ```'_Connection_'``` as the key for caching the connection object.

##### CACHE\_KEY\_ROOT

> ```'_ActiveDirectoryRoot_'``` as the key for caching the Active Directory root URL.

#### Mappings ####

##### GLOBAL\_CACHE

> A global cache of **LdapEntry** objects mapped to LDAP Urls,
> plus the connection object and the Active Directory root URL.

##### GROUP\_TYPES

> A **FlagsMapping()** with Active Directory group type bitmasks
> (values are taken from https://github.com/tjguk/active_directory/blob/master/active_directory.py#L164)

##### AUTHENTICATION\_TYPES

> A **FlagsMapping()** with Active Directory authentication type bitmasks
> (values are taken from https://github.com/tjguk/active_directory/blob/master/active_directory.py#L172)

##### SAM\_ACCOUNT\_TYPES

> A **UnsignedIntegerMapping()** with Active Directory account type magic numbers
> (values are taken from https://github.com/tjguk/active_directory/blob/master/active_directory.py#L187)

##### USER\_ACCOUNT\_CONTROL

> A **FlagsMapping()** with Active Directory user account state bitmasks
> (values are taken from https://github.com/tjguk/active_directory/blob/master/active_directory.py#L202)

##### SEARCH\_FILTERS

> A dict of **SearchFilter** instances mapped to the following keywords:
> * ```'computer'``` for searching computers by ```cn```
> * ```'group'``` for searching groups by ```cn```
> * ```'ou'``` for searching organizational units by ```ou```
> * ```'public_folder'``` for searching public folders by ```displayName```
> * ```'userid'``` for searching users by ```sAMAccountName```


### Classes

#### UnsignedIntegerMapping(_\*\*kwargs_)

A Mapping of unsigned integers to names with reverse lookup functionality.
Member access using a name returns the associated number and vice versa.

##### .get\_name(_number_)

> Explicitly returns the name associated with the given number.


#### FlagsMapping(_\*\*kwargs_)

An **UnsignedIntegerMapping** subclass for bitmasks mapped to flag names

##### .get\_flag\_names(_number_)

> Returns a set of all flag names for the bitmasks matching the given number.


#### Recordset(_record_)

Wrapper around an ADO recordset as documented at
https://docs.microsoft.com/windows/win32/adsi/searching-with-activex-data-objects-ado

##### .query(_query\_string, \*\*kwargs_)

> _Classmethod_ that executes an Active Directory query over a cached connection
> (provided by the **connection()** helper function, see source code)
> and returns an iterator over **RecordSet** instances for each found result.

> The query may be parameterized using keyword arguments.
> Underscores in the keywords will be replaced by spaces.

> The following parameters are preset for the query but may be overridden:
> * Asynchronous=True
> * Timeout=1

##### .dump\_fields()

> Returns an iterator over the recordset fields as (name, value) tuples


#### PathComponent(_keyword, value_)

Instances of this class represent a single component of an LDAP path, eg ```'cn=Users'```.
They are initialized with a keyword and a value, in this example: ```'cn'``` and ```'Users'```.

##### .keyword

> The keyword

##### .value

> The value

##### .from\_string(string)

> _Constructor (class)method_, returns a **PathComponent** instance built from keyword and value determined by splitting _string_ at a non-escaped equals sign (```=```).


#### LdapPath(_\*parts_)

Instances of this class represent an LDAP path.
They are initialized using the provided parts, which can be either strings or **PathComponent** instances.

##### .components

> The components of the path (a tuple of **PathComponent** instances)

##### .rdn

> The relative distinguished name of the LPAP path (the **.value** of the first component)

##### .url

> The LDAP URL of the path (the distinguished name prefixed with ```'LDAP://'```)

##### .from\_string(string)

> _Constructor (class)method_, returns an **LdapPath** instance built from the provided _string_ splitted at all non-escaped commas (```,```).


#### SearchFilter(_primary\_key\_name, \*\*fixed_parameters_)

Instances of this class hold a primary key name and a mapping of fixed parameters for an LDAP search.

##### .execute\_query(_ldap\_url, \*args, \*\*kwargs_)

> Return an interator from the result of an LDAP query
> (using the **RecordSet.query()** class method)
> starting at _ldap\_url_ and using SQL syntax with the 
> ```WHERE``` clause genarated by the **.where\_clause()** method.

##### .where\_clause(_\*args, \*\*kwargs_)

> Return a ```WHERE``` clause for an SQL-like LDAP query string,
> built from the provided positional and keyword arguments,
> all concatenated using ```AND```.  
> The stored fixed parameters override the provided keyword arguments.
> If a _\_primary\_key\__ keyword was provided, its value is
> built into the clause using the stored primary key name.


#### LdapEntry(_com\_object_)

Stores a subset of an LDAP entry's attributes.
The stored attributes can be accessed via item access using \[_attribute\_name_\]
or (in the case of suitable attribute names) via attribute access using ._attribute\_name_

Note: LDAP entry attribute names are case insensitive.

All **LdapPath** and subclasses instances should be instantiated 
by using the **produce\_entry()** function below.

##### .empty\_attributes

> A frozenset of the names of all attributes having the value None.

##### .ldap\_url

> The LDAP URL of the entry.

##### .child(_single\_path\_component_)

> Returns an **LdapEntry** subclass instance for a relative child of this instance.
> Its path is determined by prepending the _single\_path\_component_ to this instance's path. 

##### .stored\_attributes\_items()

> Returns an items dictview of the internal mapping of stored attributes.
> Please note that empty attributes are not contained here; only their names
> are stored in the **.empty\_attributes** frozenset.

##### .print\_dump()

> Prints a case-sensitive (i.e. uppercase before lowercase) alphabetically sorted dump
> of all non-empty attributes.


#### User(_com\_object_)

**LdapEntry** subclass for Active Directory users

Interesting attributes include:
* ```sAMAccountName``` - the user ID
* ```givenName``` - the first name
* ```sn``` - the last name
* ```title``` - eg a PhD
* ```manager``` - the user's direct boss (distinguished name)
* ```memberOf``` - all groups the user is a direct member of (a tuple of distinguished names)
* ```userAccountControl``` - originally a number, but resolved to a set of flag names from **USER\_ACCOUNT\_CONTROL**

##### .account\_disabled

> ```True``` if the account is disabled, ```False``` if it is active.  


#### Group(_com\_object_)

**LdapEntry** subclass for Active Directory groups

Interesting attributes include:
* ```member``` - all direct members (users and groups, a tuple of distinguished names)
* ```memberOf``` - all groups this group is a direct member of (a tuple of distinguished names)

##### .walk()

> Returns an iterator over tuples, each consisting of: _1._ the current **Group** instance,
> _2._ a list of member **Group** instances and _3._ a list of member **User** instances.


### Public interface functions

#### produce\_entry(_ldap\_path, lazy=True_)

> **LdapEntry** and subclasses factory function.

> Determines the suitable class out of **LdapEntry**, **User** or **Group** from the
> COM object found at the LDAP URL.
> Generates an instance of this class from the COM object,
> stores it in **GLOBAL\_CACHE** (associated to the LDAP path URL),
> and returns the Instance.

> _ldap\_path_ may be a string containing either a distinguished name or an LDAP URL
> (which is basically a distinguished name prefixed with ```'LDAP://'```),
> or an **LdapPath** instance.

> if _lazy_ is set to ```True``` (the default), this function returns
> the suitable cached entry if it exists, avoiding expensive lookups
> and network traffic.

#### root(_server=None_)

> Returns the (cached) **LdapEntry** instance referring to the
> root of the logged-on Active Directory tree.

#### search(_\*args, active=None, search\_base=None, search\_filter=None, \*\*kwargs_)

> Returns an iterator over all found LDAP paths
> from an LDAP search starting at the LDAP URL specified as _search\_base_.
> If _search\_base_ is not given, the LDAP search starts at the LDAP URL of root().

> If _active_ is set to ```True``` or ```False``` explicitly, the method returns only
> the paths of active (or deactivated) matching entries. 

> If _search_filter_ is set to a SearchFilter instance,
> this method uses that instance to search the Active Directory.
> Else, if a keyword matching any of the **SEARCH\_FILTERS** keys
> was provided, that search filter is used with this keyword's value
> specified as the _\_primary\_key\__ keyword's value.  
> In all other cases, an empty search filter
> will be instantiated and used.

> If positional arguments (_\*args_) were provided and any of them
> does not contain a valid condition for the query's ```WHERE``` clause,
> the **RecordSet.query()** method execting the query will return a ValueError
> and display the faulty query string.

#### search\_users(_\*args, \*\*kwargs_)

> Returns an iterator over all found LDAP paths like the **search()** function above,
> but uses the user search filter (**SEARCH\_FILTER\[**```'userid'```**\]**) unconditionally.

> In contrary to plain **search()**, the first
> positional argument - if any are provided - is treated differently from the rest:  
> It is matched against each one of ```sAMAccountName```, ```displayName``` and ```cn```
> by building suitable conditions joined by ```'OR'```.
> The remaining positional arguments are treated normally.

#### get\_first\_entry(_\*args, \*\*kwargs_)

> Returns an **LdapEntry** or subclass instance made from the first found LDAP entry
> from an LDAP search using **search()**, or None if nothing was found.

#### get\_first\_user(_\*args, \*\*kwargs_)

> Returns a **User** instance made from the first found LDAP entry
> from an LDAP search using **search\_users()**, or None if nothing was found.


## Examples

```python
import read_ad

# read_ad.root() returns the cached Active Directory root entry

# find your own user in active directory
import getpass
my_user = read_ad.get_first_user(getpass.getuser())

```
