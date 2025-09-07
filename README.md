```
             _,.---._    ,--.--------.   _,.---._                                        
   _.-.    ,-.' , -  `. /==/,  -   , -\,-.' , -  `.   .-.,.---.   _,..---._     _..---.  
 .-,.'|   /==/_,  ,  - \\==\.-.  - ,-./==/_,  ,  - \ /==/  `   \/==/,   -  \  .' .'.-. \ 
|==|, |  |==|   .=.     |`--`\==\- \ |==|   .=.     |==|-, .=., |==|   _   _\/==/- '=' / 
|==|- |  |==|_ : ;=:  - |     \==\_ \|==|_ : ;=:  - |==|   '='  /==|  .=.   ||==|-,   '  
|==|, |  |==| , '='     |     |==|- ||==| , '='     |==|- ,   .'|==|,|   | -||==|  .=. \ 
|==|- `-._\==\ -    ,_ /      |==|, | \==\ -    ,_ /|==|_  . ,'.|==|  '='   //==/- '=' ,|
/==/ - , ,/'.='. -   .'       /==/ -/  '.='. -   .' /==/  /\ ,  )==|-,   _`/|==|   -   / 
`--`-----'   `--`--''         `--`--`    `--`--''   `--`-`--`--'`-.`.____.' `-._`.___,'  
     auth: smurfd 2024   Database, sneaky like natures bandit
```
`https://en.wikipedia.org/wiki/Raccoon`


Database and Key value store written in C & Python. No dependencies.

#### Usage Python backend
```
PYTHONPATH="." python3 lotordb/server.py keys  # Run in one terminal, key value store server
PYTHONPATH="." python3 lotordb/client.py keys  # Run in one terminal, key value store client

PYTHONPATH="." python3 lotordb/server.py tables  # Run in one terminal, table server
PYTHONPATH="." python3 lotordb/client.py tables  # Run in one terminal, table client
```
##### Test Python backend
```
python3 -m pytest lotordb/test
```

#### Usage C backend
```
make -Clotordb/src  # Builds and runs test suite

./lotordb/src/.build/tests server keys  # Run in one terminal, key value store server
./lotordb/src/.build/tests client keys  # Run in one terminal, key value store client

./lotordb/src/.build/tests server tables  # Run in one terminal, table server
./lotordb/src/.build/tests client tables  # Run in one terminal, table client
```
"[o.o]"
