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

**GROUP_TYPES**

> A **FlagsMapping()** with assignments taken from upstream (see https://github.com/tjguk/active_directory/blob/master/active_directory.py#L164)

**GLOBAL_CACHE**

> A global cache of LdapEntry objects mapped to LDAP Urls

_(tbc)_

### Classes

#### UnsignedIntegerMapping(_\*\*kwargs_)

A Mapping of unsigned integers to names with reverse lookup functionality

#### FlagsMapping(_\*\*kwargs_)

An **UnsignedIntegerMapping** subclass for flags

_(tba)_

### Public interface functions

#### produce_entry(_ldap\_path, lazy=True_)

#### root(_server=None_)

#### find(_\*args, \*\*kwargs_)

#### find_user(_\*args, \*\*kwargs_)

#### search(_\*args, \*\*kwargs_)

#### search_explicit(_query\_string_)

_(tbc)_

## Examples

```python
import read_ad

# read_ad.root() returns the cached Active Directory root entry

# find your own user in active directory
import getpass
my_user = read_ad.find_user(getpass.getuser())

```
