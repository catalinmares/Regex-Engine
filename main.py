#!/usr/bin/env python
import sys
import pickle
import string
import types

from regex import RegEx
from regular_expression import RegularExpression
from nfa import NFA
from dfa import DFA

CHARSET = string.digits + string.ascii_letters

# Constante simbolice pentru RegEx
RX_EMPTY_STRING = 0
RX_SYMBOL_SIMPLE = 1
RX_SYMBOL_ANY = 2
RX_SYMBOL_SET = 3
RX_MAYBE = 4
RX_STAR = 5
RX_PLUS = 6
RX_RANGE = 7
RX_CONCATENATION = 8
RX_ALTERNATION = 9

# Constante simbolice pentru RegularExpression
RE_EMPTY_SET = 0
RE_EMPTY_STRING = 1
RE_SYMBOL = 2
RE_STAR = 3
RE_CONCATENATION = 4
RE_ALTERNATION = 5

def apply_transformations(regex_string, pos, symbol_regex):
    while pos < len(regex_string):
        if regex_string[pos] == '*':
            symbol_regex = RegEx(RX_STAR, symbol_regex)
            pos = pos + 1
        elif regex_string[pos] == '+':
            symbol_regex = RegEx(RX_PLUS, symbol_regex)
            pos = pos + 1
        elif regex_string[pos] == '?':
            symbol_regex = RegEx(RX_MAYBE, symbol_regex)
            pos = pos + 1
        elif regex_string[pos] == '{':
            if regex_string[pos + 1] == ',':
                symbol_regex = RegEx(RX_RANGE, symbol_regex, (-1, int(regex_string[pos + 2])))
                pos = pos + 4
            elif regex_string[pos + 2] == ',':
                if regex_string[pos + 3] == '}':
                    symbol_regex = RegEx(RX_RANGE, symbol_regex, (int(regex_string[pos + 1]), -1))
                    pos = pos + 4
                elif regex_string[pos + 4] == '}':
                    symbol_regex = RegEx(RX_RANGE, symbol_regex, (int(regex_string[pos + 1]), int(regex_string[pos + 3])))       
                    pos = pos + 5
            else:
                symbol_regex = RegEx(RX_RANGE, symbol_regex, (int(regex_string[pos + 1]), int(regex_string[pos + 1])))
                pos = pos + 3
        else:
            break

    return (symbol_regex, pos)

def build_set(regex_string, pos):
    symbol_set = set()

    while regex_string[pos] != ']':
        if regex_string[pos] in CHARSET:
            if regex_string[pos + 1] == '-':
                symbol_set.add((regex_string[pos], regex_string[pos + 2]))
                pos = pos + 3
            else:
                symbol_set.add(regex_string[pos])
                pos = pos + 1

    return (RegEx(RX_SYMBOL_SET, symbol_set), pos)


def get_parsed_regex(regex_string, startpoint, endpoint):
    regex = None
    i = startpoint

    while i < endpoint:
        if regex_string[i] in CHARSET:
            symbol_regex = RegEx(RX_SYMBOL_SIMPLE, regex_string[i])

            (new_symbol_regex, i) = apply_transformations(regex_string, i + 1, symbol_regex)
            
            if regex == None:
                regex = new_symbol_regex
            else:
                regex = RegEx(RX_CONCATENATION, regex, new_symbol_regex)
        elif regex_string[i] == '[':
            (symbol_set, i) = build_set(regex_string, i + 1)

            (new_symbol_set, i) = apply_transformations(regex_string, i + 1, symbol_set)

            if regex == None:
                regex = new_symbol_set
            else:
                regex = RegEx(RX_CONCATENATION, regex, new_symbol_set)
        elif regex_string[i] == '.':
            symbol_any = RegEx(RX_SYMBOL_ANY)
            i = i + 1

            if regex == None:
                regex = symbol_any
            else:
                regex = RegEx(RX_CONCATENATION, regex, symbol_any)
        elif regex_string[i] == '(':
            j = i + 1

            stack = ['(']

            while len(stack) != 0:
                if regex_string[j] == '(':
                    stack.append('(')
                elif regex_string[j] == ')':
                    stack.pop()

                if len(stack) != 0:
                    j = j + 1

            parenthesis_expr = get_parsed_regex(regex_string, i + 1, j)
            i = j + 1

            (new_parenthesis_expr, i) = apply_transformations(regex_string, i, parenthesis_expr)

            if regex == None:
                regex = new_parenthesis_expr
            else:
                regex = RegEx(RX_CONCATENATION, regex, new_parenthesis_expr)
        elif regex_string[i] == '|':
            j = i + 1

            while j < endpoint:
                if regex_string[j] == '|':
                    break;

                j = j + 1

            if j == endpoint:
                j = j + 1

            alternation_expr = get_parsed_regex(regex_string, i + 1, j - 1)

            if j == (endpoint + 1):
                i = endpoint
            else:
                i = j

            regex = RegEx(RX_ALTERNATION, regex, alternation_expr)

    return regex

def regex_to_re(regex):
    if regex.type == RX_EMPTY_STRING:
        return RegularExpression(RE_EMPTY_STRING)

    if regex.type == RX_SYMBOL_SIMPLE:
        return RegularExpression(RE_SYMBOL, regex.symbol)

    if regex.type == RX_SYMBOL_ANY:
        regular_expr = None

        for char in CHARSET:
            symbol_expr = RegularExpression(RE_SYMBOL, char)

            if regular_expr == None:
                regular_expr = symbol_expr
            else:
                regular_expr = RegularExpression(RE_ALTERNATION, regular_expr, symbol_expr)

        return regular_expr

    if regex.type == RX_SYMBOL_SET:
        regular_expr = None

        for elem in regex.symbol_set:
            if not(type(elem) is tuple):
                symbol_expr = RegularExpression(RE_SYMBOL, elem)

                if regular_expr == None:
                    regular_expr = symbol_expr
                else:
                    regular_expr = RegularExpression(RE_ALTERNATION, regular_expr, symbol_expr)
            else:
                for num in range(ord(elem[0]), ord(elem[1]) + 1):
                    symbol_expr = RegularExpression(RE_SYMBOL, chr(num))

                    if regular_expr == None:
                        regular_expr = symbol_expr
                    else:
                        regular_expr = RegularExpression(RE_ALTERNATION, regular_expr, symbol_expr)

        return regular_expr

    if regex.type == RX_MAYBE:
        return RegularExpression(RE_ALTERNATION, RegularExpression(RE_EMPTY_STRING), regex_to_re(regex.lhs))

    if regex.type == RX_STAR:
        return RegularExpression(RE_STAR, regex_to_re(regex.lhs))

    if regex.type == RX_PLUS:
        regular_expr = regex_to_re(regex.lhs)

        return RegularExpression(RE_CONCATENATION, regular_expr, RegularExpression(RE_STAR, regular_expr))

    if regex.type == RX_RANGE:
        body_expr = regex_to_re(regex.lhs)

        if regex.range[0] == regex.range[1]:    # Exact x aparitii
            regular_expr = body_expr

            for i in range(0, regex.range[0] - 1):
                regular_expr = RegularExpression(RE_CONCATENATION, regular_expr, body_expr)

            return regular_expr

        if regex.range[0] == -1:    # Cel mult y aparitii
            regular_expr = RegularExpression(RE_EMPTY_STRING)

            for i in range(0, regex.range[1]):
                aux_expr = body_expr

                for j in range(1, i + 1):
                    aux_expr = RegularExpression(RE_CONCATENATION, aux_expr, body_expr)

                regular_expr = RegularExpression(RE_ALTERNATION, regular_expr, aux_expr)

            return regular_expr

        if regex.range[1] == -1:    # Cel putin x aparitii
            regular_expr = body_expr

            for i in range(1, regex.range[0]):
                regular_expr = RegularExpression(RE_CONCATENATION, regular_expr, body_expr)

            regular_expr = RegularExpression(RE_CONCATENATION, regular_expr, RegularExpression(RE_STAR, body_expr))

            return regular_expr

        if regex.range[0] != regex.range[1]:    # Intre x si y aparitii
            regular_expr = None

            for i in range(regex.range[0], regex.range[1] + 1):
                aux_expr = body_expr

                for j in range(1, i):
                    aux_expr = RegularExpression(RE_CONCATENATION, aux_expr, body_expr)

                if regular_expr == None:
                    regular_expr = aux_expr
                else:
                    regular_expr = RegularExpression(RE_ALTERNATION, regular_expr, aux_expr)

            return regular_expr

    if regex.type == RX_CONCATENATION:
        return RegularExpression(RE_CONCATENATION, regex_to_re(regex.lhs), regex_to_re(regex.rhs))

    if regex.type == RX_ALTERNATION:
        return RegularExpression(RE_ALTERNATION, regex_to_re(regex.lhs), regex_to_re(regex.rhs))

def rename_states(target, reference):
    offset = max(reference.states) + 1
    target.start_state += offset
    target.states = set(map(lambda s: s + offset, target.states))
    target.final_states = set(map(lambda s: s + offset, target.final_states))
    new_delta = {}
    
    for (state, symbol), next_states in target.delta.items():
        new_next_states = set(map(lambda s: s + offset, next_states))
        new_delta[(state + offset, symbol)] = new_next_states

    target.delta = new_delta


def new_states(*nfas):
    state = 0
    
    for nfa in nfas:
        m = max(nfa.states)
        
        if m >= state:
            state = m + 1

    return state, state + 1


def kleene(nfa1):
    initial_state, final_state = new_states(nfa1)

    nfa = NFA(CHARSET, {initial_state, final_state}, initial_state, {final_state}, {})

    for state in nfa1.states:
        nfa.states.add(state)

    new_delta = {}

    for (state, symbol), next_states in nfa1.delta.items():
        new_delta.update({(state, symbol): next_states})

    for stop_state in nfa1.final_states:
        if (stop_state, "") in nfa1.delta:
            new_next_states = nfa1.delta[(stop_state, "")]
            new_next_states.add(final_state)
            new_delta.update({(stop_state, ""): new_next_states})
        else:
            new_delta.update({(stop_state, ""): {final_state}})

    new_delta.update({(initial_state, ""): {nfa1.start_state, final_state}})
    new_delta.update({(final_state, ""): {initial_state}})

    nfa.delta = new_delta
  
    return nfa

def concat(nfa1, nfa2):
    rename_states(nfa2, nfa1)
    initial_state, final_state = new_states(nfa1, nfa2)
  
    nfa = NFA(CHARSET, {initial_state, final_state}, initial_state, {final_state}, {})
  
    new_delta = {}
    new_delta.update({(initial_state, ""): {nfa1.start_state}})
  
    for stop_state in nfa1.final_states:
        if (stop_state, "") in nfa1.delta:
            new_next_states = nfa1.delta[(stop_state, "")]
            new_next_states.add(nfa2.start_state)
            new_delta.update({(stop_state, ""): new_next_states})
        else:
            new_delta.update({(stop_state, ""): {nfa2.start_state}})
  
    for stop_state in nfa2.final_states:
        if (stop_state, "") in nfa2.delta:
            new_next_states = nfa2.delta[(stop_state, "")]
            new_next_states.add(final_state)
            new_delta.update({(stop_state, ""): new_next_states})
        else:
            new_delta.update({(stop_state, ""): {final_state}})
  
    for state in nfa1.states:
        nfa.states.add(state)
  
    for state in nfa2.states:
        nfa.states.add(state)
  
    for (state, symbol), next_states in nfa1.delta.items():
        if state in nfa1.final_states and symbol == "":
            pass

        new_delta.update({(state, symbol): next_states})
  
    for (state, symbol), next_states in nfa2.delta.items():
        if state in nfa2.final_states and symbol == "":
            pass

        new_delta.update({(state, symbol): next_states})
  
    nfa.delta = new_delta
  
    return nfa

def alternate(nfa1, nfa2):
    rename_states(nfa2, nfa1)
    initial_state, final_state = new_states(nfa1, nfa2)
  
    nfa = NFA(CHARSET, {initial_state, final_state}, initial_state, {final_state}, {})

    for state in nfa1.states:
        nfa.states.add(state)
  
    for state in nfa2.states:
        nfa.states.add(state)
  
    new_delta = {}
    new_delta.update({(initial_state, ""): {nfa1.start_state, nfa2.start_state}})

    for stop_state in nfa1.final_states:
        if (stop_state, "") in nfa1.delta:
            new_next_states = nfa1.delta[(stop_state, "")]
            new_next_states.add(final_state)
            new_delta.update({(stop_state, ""): new_next_states})
        else:
            new_delta.update({(stop_state, ""): {final_state}})
  
    for stop_state in nfa2.final_states:
        if (stop_state, "") in nfa2.delta:
            new_next_states = nfa2.delta[(stop_state, "")]
            new_next_states.add(final_state)
            new_delta.update({(stop_state, ""): new_next_states})
        else:
            new_delta.update({(stop_state, ""): {final_state}})

    for (state, symbol), next_states in nfa1.delta.items():
        if state in nfa1.final_states and symbol == "":
            pass

        new_delta.update({(state, symbol): next_states})
  
    for (state, symbol), next_states in nfa2.delta.items():
        if state in nfa1.final_states and symbol == "":
            pass

        new_delta.update({(state, symbol): next_states})
  
    nfa.delta = new_delta
  
    return nfa

def re_to_nfa(re):
    if (re.type == RE_EMPTY_SET):
        return NFA(CHARSET, {0}, 0, {}, {})
    
    if (re.type == RE_EMPTY_STRING):
        return NFA(CHARSET, {0}, 0, {0}, {})
    
    if (re.type == RE_SYMBOL):
        return NFA(CHARSET, {0, 1}, 0, {1}, {(0, re.symbol): {1}})
    
    if (re.type == RE_STAR):
        return kleene(re_to_nfa(re.lhs))
    
    if (re.type == RE_CONCATENATION):
        return concat(re_to_nfa(re.lhs), re_to_nfa(re.rhs))
    
    if (re.type == RE_ALTERNATION):
        return alternate(re_to_nfa(re.lhs), re_to_nfa(re.rhs))

def get_epsilon_closure(state, nfa):
    checked = {}
    to_check = list(state)

    for nfa_state in nfa.states:
        checked[nfa_state] = False

    # Eliminare epsilon-tranzitii pt starea curenta
    while len(to_check) != 0:
        aux_state = to_check[0]
        to_check.remove(aux_state)
        checked[aux_state] = True

        if (aux_state, "") in nfa.delta:
            epsilon_closure = nfa.delta[(aux_state, "")]
        else:
            epsilon_closure = {}

        for adj_state in epsilon_closure:
            if adj_state != aux_state:
                if not(checked[adj_state]):
                    to_check.append(adj_state)
                    
                state.add(adj_state)

    return state

def nfa_to_dfa(nfa):
    states = []
    start_state = {nfa.start_state}
    final_states = []
    delta = {}

    # Adaugare stare noua pentru sink-state
    new_state = new_states(nfa)
    sink_state = {new_state[0]}

    for symbol in CHARSET:
        delta.update({(repr(sink_state), symbol): sink_state})

    stack = []
    start_state = get_epsilon_closure(start_state, nfa)
    stack.append(start_state)
    checked_stack = []

    # Constructie set de stari
    while len(stack) != 0:
        current_state = stack.pop()
        checked_stack.append(current_state)
        states.append(current_state)

        # Adaugare stare initiala
        if nfa.start_state in current_state and start_state == None:
            start_state = current_state

        # Determinare stari adiacente
        for symbol in CHARSET:
            next_states = set()

            for state in current_state:
                if (state, symbol) in nfa.delta:
                    adj_states = set(nfa.delta[(state, symbol)])
                else:
                    adj_states = set()

                for adj_state in adj_states:
                    next_states.add(adj_state)

            # Delta trebuie sa fie totala - 
            # daca am gasit tranzitii, trec in noile stari
            # altfel trec in sink-state
            if next_states != set():
                all_next_states = get_epsilon_closure(next_states, nfa)
                delta.update({(repr(current_state), symbol): all_next_states})
            else:
                delta.update({(repr(current_state), symbol): sink_state})

            # Ma asigur ca nu revizitez o stare deja vizitata
            if not(next_states in checked_stack):
                stack.append(next_states)

    # Determinare stari finale
    for state in states:
        for final_state in nfa.final_states:
            if final_state in state:
                final_states.append(state)
                break

    return DFA(CHARSET, states, start_state, final_states, delta, sink_state)


def accept(dfa, w):
    current_state = dfa.start_state
    
    for i in range(0, len(w) - 1):
        current_state = dfa.delta[(repr(current_state), w[i])]

        if current_state == dfa.sink_state:
            return False
  
    if current_state in dfa.final_states:
        return True
    else:
        return False

if __name__ == "__main__":
    valid = (len(sys.argv) == 4 and sys.argv[1] in ["RAW", "TDA"]) or \
            (len(sys.argv) == 3 and sys.argv[1] == "PARSE")
    if not valid:
        sys.stderr.write(
            "Usage:\n"
            "\tpython3 main.py RAW <regex-str> <words-file>\n"
            "\tOR\n"
            "\tpython3 main.py TDA <tda-file> <words-file>\n"
            "\tOR\n"
            "\tpython3 main.py PARSE <regex-str>\n"
        )
        sys.exit(1)

    if sys.argv[1] == "TDA":
        tda_file = sys.argv[2]
        with open(tda_file, "rb") as fin:
            parsed_regex = pickle.loads(fin.read())
    else:
        regex_string = sys.argv[2]

        # TODO "regex_string" conține primul argument din linia de comandă,
        # șirul care reprezintă regexul cerut. Apelați funcția de parsare pe el
        # pentru a obține un obiect RegEx pe care să-l stocați în
        # "parsed_regex"
        #
        # Dacă nu doriți să implementați parsarea, puteți ignora această parte.
        parsed_regex = get_parsed_regex(regex_string, 0, len(regex_string))
        if sys.argv[1] == "PARSE":
            print(str(parsed_regex))
            sys.exit(0)

    # În acest punct, fie că a fost parsat, fie citit direct ca obiect, aveți
    # la dispoziție variabila "parsed_regex" care conține un obiect de tip
    # RegEx. Aduceți-l la forma de Automat Finit Determinist, pe care să puteți
    # rula în continuare.

    #print(str(parsed_regex))

    regular_expression = regex_to_re(parsed_regex)
    #print(str(regular_expression))

    nfa = re_to_nfa(regular_expression)

    dfa = nfa_to_dfa(nfa)

    with open(sys.argv[3], "r") as fin:
        content = fin.readlines()

    for word in content:
        # TODO la fiecare iterație, "word" conținue un singur cuvânt din
        # fișierul de input; verificați apartenența acestuia la limbajul
        # regexului dat și scrieți rezultatul la stdout.
        if accept(dfa, word):
            print("True")
        else:
            print("False")
