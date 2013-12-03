vzp_vac
=======

windows vulnerability assessment collection tool

Background and looking forward:
initially looking to gather information on the systems after most exploits and things have been run to determine
if other escalation and exploit vectors exist.

We also want to look through audit, AV, and HIPS logs to determine if any indicators were present
to show defenders how to look for them in real attacks.

We would also like to gather this info from many systems quickly and analyze it.  To that end we'll be getting
most of it into a SQLite database or something so that we can generate some system wide canned reports and some 
cusomized reports.  That beats sifting through a few hundred flat files.


Usage:
Straighforward...run it with no arguments.
Will prompt for the directory where you have the sysinternals suite installed.  You will also need
the sysinternals-eulas.reg file in the same directory you have the sysinternals tools installed to.

Output:
creates a directory at c:\assessment to hold the files for that system.
