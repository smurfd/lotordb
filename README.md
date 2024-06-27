```
@@@       @@@@@@  @@@@@@@  @@@@@@  @@@@@@@  @@@@@@@  @@@@@@@
@@!      @@!  @@@   @@!   @@!  @@@ @@!  @@@ @@!  @@@ @@!  @@@
@!!      @!@  !@!   @!!   @!@  !@! @!@!!@!  @!@  !@! @!@!@!@
!!:      !!:  !!!   !!:   !!:  !!! !!: :!!  !!:  !!! !!:  !!!
: ::.: :  : :. :     :     : :. :   :   : : :: :  :  :: : ::
     auth: smurfd 2024   Database, sneaky like natures bandit
```
`https://en.wikipedia.org/wiki/Raccoon`


### lotordb
Database and Key value store written in Python. No dependencies.

### test
```
python3 -m pytest lotordb/test
```

### TODO
The database

### Usage
Start Table server in one terminal: `PYTHONPATH="." python3 lotordb/server.py table`<br>
Start Key server in one terminal: `PYTHONPATH="." python3 lotordb/server.py key`<br>
Start Table client in one terminal: `PYTHONPATH="." python3 lotordb/client.py table`<br>
Start Key client in one terminal: `PYTHONPATH="." python3 lotordb/client.py key`<br>

### C backend
```
make -Clotordb/src
./lotordb/src/server keys (in one terminal, keyvalue store server)
./lotordb/src/client keys (in one terminal, keyvalue store client)

./lotordb/src/server tables (in one terminal, table server)
./lotordb/src/client tables (in one terminal, table client)
```
"[o.o]"
