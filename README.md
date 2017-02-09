SHACollider
===========


Synopsis
--------

SHA-256 prefix collision finder via cyclic hashing.


Acknowledgments
---------------

This program uses a bit-oriented SHA-256 implementation written by Jens Thoms Toerring <<jt@toerring.de>> and published under GNU General Public License version 2 at <http://users.physik.fu-berlin.de/~jtt/sha_digest.html>.

Computed hashes are added into an in-memory bloom filter implementation by Jyri J. Virkki <<jyri@virkki.com>> released under the BSD 2-clause license and available at <https://github.com/jvirkki/libbloom> with a bugfix by Roey Berman <<roey@everything.me>>.

LevelDB by Sanjay Ghemawat <<sanjay@google.com>> and Jeff Dean <<jeff@google.com>> is used to store a hash-to-data mapping on disk for verifying bloom filter hits, available under the 3-clause BSD license at <https://github.com/google/leveldb>.


License
-------

Copyright (C) 2017 JohnHoder, daniel-lc, phagara

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
