# Regex Engine

In implementarea proiectului am urmat intocmai pasii urmatorii pasi:

**1. Parsare regex**

Am implementat o functie recursiva care primeste un string
si intoarce o conversie in regex a unui interval din acel
string. Apelul initial este pe intregul interval al stringului.
In momentul in care se intalnesc paranteze, se apeleaza recursiv
si rezultatul intors va fi regex-ul parsat din interiorul parantezelor.
Analog pentru alternare, se apeleaza recursiv pentru a crea urmatorul
regex care sa fie alternativa regex-ului parsat pana in prezent.
La intalnirea de caractere noi din alfabet se verifica existenta unor
transformari care li se aplica (*, +, ? sau {}) si de la regex-ul
caracterului singur se construieste regex-ul caracterului caruia i se
aplica transformarile respective. Aceste transformari se aplica si
pentru regex-urile din interiorul parantezelor. Am implementat o functie
separata numita apply_transformations care are rolul de a aplica aceste
transformari.


**2. Normalizare la expresie regulata**

Pentru acest pas am implementat o functie recursiva ce are ca si cazuri
de baza EMPTY_STRING, SYMBOL_SIMPLE si SYMBOL_ANY, in timp ce pentru
celelalte tipuri m-am folosit de recursivitate. Nimic interesant sau
deosebit de explicat aici, pur si simplu am implementat bazandu-ma pe
explicatiile din cerinta.


**3. Conversie la Automat Finit Nedeterminist**

Pentru acest pas am implementat algoritmul prezentat la curs si la
laborator. De asemenea, m-am folosit de functii din laborator si am
implmentat conversia folosind 3 functii auxiliare pentru cele 3 cazuri
recursive: kleene star, concatenation si alternation. In aceste functii
nu am facut altceva decat sa modific automatele pe care le primeam ca
parametri si sa intorc un automat construit prin epsilon-tranzitii intre
automatele primite ca parametru.


**4. Conversie la Automat Finit Determinist**

Acesta mi s-a parut cel mai greu pas al proiectului. A fost foarte dificil sa
implementez o functie de conversie de la NFA la DFA, insa dupa mult chin
am reusit sa construiesc DFA-ul pornind de la NFA si modificand putin
clasa DFA oferita in schelet. Ideea conversiei este cea predata la curs.
Am pornit din starea initiala a NFA-ului, am cautat inchiderea pe epsilon
a acesteia si aceasta a reprezentat starea initiala a DFA-ului. Pentru
determinarea inchiderii pe epsilon a unei stari am implementat o functie
care porneste dintr-o stare a NFA-ului si viziteaza toate starile accesibile
prin tranzitii pe epsilon, adaugandu-le intr-o lista de stari care va fi
o noua stare a DFA-ului. Dupa ce am determinat starea DFA-ului caut tranzitii
din starile NFA-ului ce o compun si in functie de existenta lor trec in stari
noi carora le determin inchiderea pe epsilon sau trec in sink-state.
Starile finale ale DFA-ului vor fi acele stari ce contin in multimea lor o
stare finala a NFA-ului.


**5. Simularea rularii DFA-ului pe un sir**

Pentru acest pas, am implementat o functie ce parcurge un sir dat si pentru
fiecare caracter al acestuia tranziteaza dintr-o stare in alta a automatului.
La fiecare pas, se verifica daca s-a ajuns in sink-state, caz in care 
cuvantul dat nu este acceptat de automat. In momentul in care s-a consumat
cuvantul, se verifica daca automatul a ajuns intr-o stare finala. Daca da,
cuvantul dat a fost acceptat, altfel nu.
