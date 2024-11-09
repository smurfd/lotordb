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

#### Usage Python backend
Start Table server in one terminal: `PYTHONPATH="." python3 lotordb/server.py table`<br>
Start Key server in one terminal: `PYTHONPATH="." python3 lotordb/server.py key`<br>
Start Table client in one terminal: `PYTHONPATH="." python3 lotordb/client.py table`<br>
Start Key client in one terminal: `PYTHONPATH="." python3 lotordb/client.py key`<br>

##### Test Python backend
```
python3 -m pytest lotordb/test
```

#### Usage C backend
```
make -Clotordb/src
./lotordb/src/.build/tests server keys  # Run in one terminal, keyvalue store server
./lotordb/src/.build/tests client keys  # Run in one terminal, keyvalue store client

./lotordb/src/.build/tests server tables  # Run in one terminal, table server
./lotordb/src/.build/tests client tables  # Run in one terminal, table client
```
"[o.o]"
