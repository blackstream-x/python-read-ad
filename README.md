# com_ad

COM-based read access for Active Directory in Python

_forked off active_directory.py v0.6.7 by Tim Golden_

Requires Python3 and the pywin32 module (https://pypi.org/project/pywin32/)

## Usage

_(tba)_

## Examples

```python
import com_ad

# com_ad.root() returns the cached Active Directory root entry

# find your own user in active directory
import getpass
my_user = com_ad.find_user(getpass.getuser())

```
