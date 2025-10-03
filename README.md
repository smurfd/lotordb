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


Database and Key value store written in C. No dependencies (submodules i have written, yes)

#### Build
```bash
git clone https://github.com/smurfd/lotordb && cd lotordb
make -Csrc # fetches submodules if they dont exist
```

#### Usage C backend
```bash
./src/.build/tests server keys  # Run in one terminal, key value store server
./src/.build/tests client keys  # Run in one terminal, key value store client

./src/.build/tests server tables  # Run in one terminal, table server
./src/.build/tests client tables  # Run in one terminal, table client
```
"[o.o]"
