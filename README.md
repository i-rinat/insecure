About
=====

*insecure* is FUSE-based file system which aim is to enlarge
file name length limit.

Usually Linux file system limit their file name length to 255 bytes.
With use of now prevalent UTF-8 for encoding that results in 255
characters  of English text, but only 128 characters in Russian.
For some Chinese characters state's worse even more (64 chars).


Limitations
===========

It seems FUSE has limit of 1024 bytes, hard-coded in kernel. _insecure_
itself shouldn't have any limit of file name length.

How it works
============

_insecure_ uses SQLite3 database to store file names and corresponding
back-end file names. Back-end names consist of prefix and a number, and
if no one tampers database, they are unique. So if user creates name
like 'some very very <...> long sentence', it stored in database and
for actual data storage something like 'prefix_4582' created instead.

And as now every name stored in db, it becoming point of failure. If something
goes wrong and you lose db file or it becomes corrupted, you lose file
names (at the very most. Hopefully, _insecure_ does nothing to file content,
they are stored as is.)


State
=====

This program is just proof-of-concept, so thing may go wrong. It's now
must be run in single threaded mode, it may shed some file names accidentally,
it may has memory leaks and so on.

The name was chosen when I wanted to write own encryption system. That plans gone,
but even now it perfectly describes current state. It is _not_ secure. So anyone
who want use this definitely has no choice :)
