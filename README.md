Passwords Stats Script
======================

Purpose
-------

Simple script that analyses account passwords and generates hashcat masks.

Inspired by [statsgen.py](https://github.com/iphelix/pack/blob/master/statsgen.py).

Install
-------

```bash
git clone https://github.com/WhatTheSlime/PassStats/
cd PassStats
python3 pass_stats.py -h
```

Usage
-----

Analyze a simple list of passwords:

```bash
python3 pass_stats.py pass.lst
```

Analyze a simple list of passwords formated like [hashcat](https://hashcat.net/hashcat/) pot file (HASH:PASS):

```bash
python3 pass_stats.py hash:pass.lst --hashes
```

Analyze a list of passwords with related user accounts:

```bash
python3 pass_stats.py hash:pass.lst --users user:hash.lst
```

**/!\\** Statistics may change if `--user` accounts are specified because one password can be used by many users!

Analyze a list of passwords with related ntds.dit dump (just add stats on non empty hash_lm):

```bash
python3 pass_stats.py hash:pass.lst --users ntds.dit --ntds
```

Join usernames, hashes and password:

```bash
python3 pass_stats.py hash:pass.lst --users user:hash.lst --join
```

Generate Masks
--------------

Generate a list of [hashcat](https://hashcat.net/hashcat/) masks starting with the most used one:

```bash
python3 pass_stats.py pass.lst --masks
```

```bash
python3 pass_stats.py hash:pass.lst --users user:hash.lst --masks
```

**/!\\** Masks list may change if `--user` is specified because one password can be used by many users!

Use `grep` with a regular expession to filter the output of `--masks` such as:

```bash
python3 pass_stats.py pass.lst --masks | grep -E '^(\?[dlsu]){8,12}$'
```

References:
-----------

- Password Analysis and Cracking Kit: https://github.com/iphelix/pack
- Hashcat cracking tool: https://hashcat.net/hashcat/
