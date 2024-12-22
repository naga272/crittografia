"""
    Fasi crittografia Enigma:
    1) Plugboard
    2) rotori
    3) riflettore
    4) rotori (ritorno)
    5) Plugboard (repeat)
"""


"""
    FASE Plugboard:
    In questa fase, vengono convertiti 10 caratteri da una 'mappa' prestabilita.
    Quella che ho preso io è:

        'A' : 'Z', 'Z' : 'A',   # 'A' == 'Z' <--> 'Z' == 'A'
        'B' : 'Y', 'Y' : 'B',   # 'B' == 'Y' <--> 'Y' == 'B'
        'C' : 'X', 'X' : 'C',   # 'C' == 'X' <--> 'X' == 'C'
        'D' : 'W', 'W' : 'D',   # 'D' == 'W' <--> 'W' == 'D'
        'E' : 'V', 'V' : 'E',   # 'E' == 'V' <--> 'V' == 'E'
        'F' : 'U', 'U' : 'F',   # 'F' == 'U' <--> 'U' == 'F'
        'G' : 'T', 'T' : 'G',   # 'G' == 'T' <--> 'T' == 'G'
        'H' : 'S', 'S' : 'H',   # 'H' == 'S' <--> 'S' == 'H'
        'I' : 'R', 'R' : 'I',   # 'I' == 'R' <--> 'R' == 'i'
        'J' : 'Q', 'Q' : 'J'    # 'J' == 'Q' <--> 'Q' == 'J'

    Se nel testo da criptare, quindi compare un carattere di quelli mappati in questa tabella, verra' sostituito col suo equivalente

    testo input:
    CIAO
    testo output:
    XRZO

    perche':
    'C' == 'X'
    'I' == 'R'
    'A' == 'Z'
    La 'O' rimane invariata perche' non e' mappata nella tabella.
"""


"""
    FASE rotori:
    di default, i rotori hanno una loro configurazione per rappresentare i caratteri dell'alfabeto:
    il rotore 1 puo' essere: EKMFLGDQVZNTOWYHXUSPAIBRCJ
    il rotore 2 puo' essere: AJDKSIRUXBLHWTMCQGZNPYFVOE
    il rotore 3 puo' essere: BDFHJLCPRTXVZNYEIWGAKMUSQO

    queste sequenze corrispondono tutti i caratteri dell'alfabeto comune:
    ABCDEFGHIJKLMNOPQRSTUVWXYZ

    passando sempre la sequenza tradotta dalla plugboard 'XRZO' al primo rotore:
    ABCDEFGHIJKLMNOPQRSTUVW |X| YZ
    EKMFLGDQVZNTOWYHXUSPAIB |R| CJ
    Passando il carattere 'X' possiamo vedere che il suo equivalente e' il carattere 'R'

    Prima di passare al secondo carattere, il rotore gira di una posizione tutti i caratteri:
    prima: EKMFLGDQVZNTOWYHXUSPAIBRCJ
    dopo : KMFLGDQVZNTOWYHXUSPAIBRCJE

    e esegue questo procedimento per tutti i caratteri passati in input.
    A ogni ciclo completo del primo rotore (quindi quando e' stato girato per 26 volte), il secondo rotore gira di una posizione.
    Il terzo rotore quando il secondo rotore gira per 26 volte (un giro completo) incrementa di una posizione.

    Il testo viene passato prima per la crittografia del primo rotore, poi del secondo e poi del terzo:

    CIAO -> input
    XRZO -> output plugboard
    RSKU -> output rotore num. 1 (diventa il testo di input per il rotore num. 2)
    GZLP -> output rotore num. 2 (diventa il testo di input per il rotore num. 3)
    COVE -> output rotore num. 3
"""


"""
    FASE riflettore:
    Il riflettore segue lo stesso concetto logico della plugboard, 
    con l'unica differenza che viene usata un'altra mappatura.
    Nel mio caso ho fatto la seguente mappa:

        'A': 'Y', 'Y': 'A',
        'B': 'R', 'R': 'B',
        'C': 'U', 'U': 'C',
        'D': 'H', 'H': 'D',
        'E': 'Q', 'Q': 'E',
        'F': 'S', 'S': 'F',
        'G': 'L', 'L': 'G',
        'I': 'P', 'P': 'I',
        'J': 'X', 'X': 'J',
        'K': 'N', 'N': 'K',
        'M': 'O', 'O': 'M',
        'T': 'Z', 'Z': 'T',
        'V': 'W', 'W': 'V'

    l'input sara' dato dall'output del rotore numero 3 ('COVE'). 
    Quindi bisogna sostituire i caratteri di questa mappa:
    C == U
    O == M
    V == W
    E == Q

    l'output del riflettore quindi e' 'UMWQ'
"""


"""
    FASE rotori (ritorno):

    Ora bisogna prendere l'input del riflettore e darlo in pasto al rotore in modo inverso:
    Si fa il procedimento inverso rispetto a quando abbiamo passato l'output della plugboard ai tre rotori (FASE rotori),
    questa volta pero' senza incrementare i rotori:

    input:      UMWQ
    alfabeto:   ABCDEFGHIJKL |M| NOP |Q| RST |U| V |W| XYZ
    rotore:     OWYHXUSPAIBR |C| JEK |M| FLG |D| Q |V| ZNT
    --------------------------------------
    output:     DCVM

    DCVM passa poi per il secondo rotore e il risultato passa infine al terzo rotore.
"""


"""
    Fase finale (Plugboard di nuovo)
    L'output ottenuto dal terzo rotore dalla fase di reverse-rotore si deve passare in input un'altra volta alla plugboard
"""


import re


class Enigma():
    rotori = {
        "1"     : "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        "2"     : "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "3"     : "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "4"     : "ESOVPZJAYQUIRHXLNFTGKDCMWB",
        "5"     : "VZBRGITYUPSDNHLXAWMJQOFECK"
    }

    plugboard_connection = {
        # simmetria di 10 caratteri dell'alfabeto
        'A' : 'Z', 'Z' : 'A',   # 'A' == 'Z' <--> 'Z' == 'A'
        'B' : 'Y', 'Y' : 'B',   # 'B' == 'Y' <--> 'Y' == 'B'
        'C' : 'X', 'X' : 'C',   # 'C' == 'X' <--> 'X' == 'C'
        'D' : 'W', 'W' : 'D',   # 'D' == 'W' <--> 'W' == 'D'
        'E' : 'V', 'V' : 'E',   # 'E' == 'V' <--> 'V' == 'E'
        'F' : 'U', 'U' : 'F',   # 'F' == 'U' <--> 'U' == 'F'
        'G' : 'T', 'T' : 'G',   # 'G' == 'T' <--> 'T' == 'G'
        'H' : 'S', 'S' : 'H',   # 'H' == 'S' <--> 'S' == 'H'
        'I' : 'R', 'R' : 'I',   # 'I' == 'R' <--> 'R' == 'i'
        'J' : 'Q', 'Q' : 'J'    # 'J' == 'Q' <--> 'Q' == 'J'
    }

    riflettore = {
        # stesso concetto di plugboard_connection, solo con una mappatura diversa
        'A': 'Y', 'Y': 'A',
        'B': 'R', 'R': 'B',
        'C': 'U', 'U': 'C',
        'D': 'H', 'H': 'D',
        'E': 'Q', 'Q': 'E',
        'F': 'S', 'S': 'F',
        'G': 'L', 'L': 'G',
        'I': 'P', 'P': 'I',
        'J': 'X', 'X': 'J',
        'K': 'N', 'N': 'K',
        'M': 'O', 'O': 'M',
        'T': 'Z', 'Z': 'T',
        'V': 'W', 'W': 'V'
    }

    def __init__(self, testo: str):
        # settaggio iniziale della macchina Enigma
        self.__primo_rotore         = Enigma.rotori["1"]
        self.__count_primo_rotore   = 0 

        self.__secondo_rotore       = Enigma.rotori["2"]
        self.__count_secondo_rotore = 0

        self.__terzo_rotore         = Enigma.rotori["3"]


        # testo di input inserito dall'utente
        self.__input              = re.sub(r"[^A-Za-z]*", "", testo.upper())
        print("input: ", self.__input)

        ''' inizializzazione fase di crittografia '''
        # primo step: il testo viene passato alla plugboard
        self.__encrypt   = self.plugboard(self.__input)      
        print("output plugboard: ", self.__encrypt)


        # secondo step: il testo passato alla plugboard viene passato ai tre rotori
        self.__encrypt  = self.rotore_logico(1) 
        print("output rotore 1: ", self.__encrypt)
        
        self.__encrypt  = self.rotore_logico(2)
        print("output rotore 2: ", self.__encrypt)
        
        self.__encrypt  = self.rotore_logico(3)
        print("output rotore 3: ", self.__encrypt)


        # terzo step: il testo passato ai tre rotori viene passato al riflettore
        self.__encrypt  = self.riflettore_logico()
        print("output riflettore: ", self.__encrypt)


        # quarto step: il testo passato al riflettore viene passato alla fase "reverse rotori"
        self.__encrypt  = self.rotore_reverse(1)
        print("output rotore 1 reverse: ", self.__encrypt)
        
        self.__encrypt  = self.rotore_reverse(2)
        print("output rotore 2 reverse: ", self.__encrypt)
        
        self.__encrypt  = self.rotore_reverse(3)
        print("output rotore 3 reverse: ", self.__encrypt)
        

        # quinto step: deve ripassare per plugboard
        self.__encrypt   = self.plugboard(self.__encrypt)
        print("output plugboard", self.__encrypt)


    def plugboard(self, testo: str) -> str:
        """
        - Regole:
        1) il numero di connessioni massimo 10 su 26 lettere (quelle non connesse sono invariate)
        2) Simmetria: 'A' == 'Z' <--> 'Z' == 'A'
        """
        text_new_mapped = ''
        for char in testo:
            text_new_mapped += Enigma.plugboard_connection.get(char, char)

        return text_new_mapped
        

    def rotore_logico(self, num_rotore: int):
        '''
            ABCDEFGHIJKLMNOPQRSTUVWXYZ
            EKMFLGDQVZNTOWYHXUSPAIBRCJ

            esempio traduzione:
            la 'A' diventa 'E'

            il rotore dopo aver tradotto il carattere gira di una posizione, diventando:
            JEKMFLGDQVZNTOWYHXUSPAIBRC

            viene preso il secondo carattere di input: 
            la 'B' diventa 'E'
            e rigira (fa così fino a quando non finisce l'input)
            A ogni giro completo (26 rotazioni) del primo rotore, il secondo rotore deve rotare di una posizione

            ------------------------------------------------------------------------------------
            L'arg num_rotore indica se stiamo al primo, secondo o terzo
        '''

        result_rotore = ''

        stringa = self.__encrypt
        for char in stringa:
            x = ord(char) - ord('A')                # trovo la posizione del carattere nell'alfabeto standard
            result_rotore += Enigma.rotori[str(num_rotore)][x]     # trovo la posizione del carattere con cui devo sostituire 

            # a ogni carattere tradotto, il primo rotore "gira" di una posizione
            self.gira_rotore(1)
            self.__count_primo_rotore += 1
            
            if self.__count_primo_rotore % 26 == 0: 
                # se il primo fa un giro completo, il secondo deve incrementare di una posizione
                self.gira_rotore(2)
                self.__count_secondo_rotore += 1

                if self.__count_secondo_rotore % 26 == 0: 
                    # se il secondo fa un giro completo, il terzo deve incrementare di una posizione
                    self.gira_rotore(3)

        return result_rotore

    
    def gira_rotore(self, num_rotore: int):
        '''
        funzione che ha il compito di far girare i rotori della macchina Enigma.
        In questo modo i caratteri non verranno tradotti sempre nello stesso identico modo
        '''
        Enigma.rotori[str(num_rotore)] = Enigma.rotori[str(num_rotore)][1:] + Enigma.rotori[str(num_rotore)][0]


    def riflettore_logico(self):
        """
        - Regole:
            Il concetto e' molto simile a quello di plugboard, con l'unica differenza nella mappatura
        """
        text_replaced = ''
        for char in self.__encrypt:
            text_replaced += Enigma.riflettore.get(char, char)

        return text_replaced


    def rotore_reverse(self, rotore_num):
        """
            e' l'inverso rispetto alla fase rotori, con l'unica differenza
            che non si devono incrementare i rotori.
            
            Ora bisogna prendere l'input del riflettore e darlo in pasto al rotore in modo inverso:
            Si fa il procedimento inverso rispetto a quando abbiamo passato l'output della plugboard ai tre rotori (FASE rotori),
            questa volta pero' senza incrementare i rotori:
            input:      UMWQ
            alfabeto:   ABCDEFGHIJKL |M| NOP |Q| RST |U| V |W| XYZ
            rotore:     OWYHXUSPAIBR |C| JEK |M| FLG |D| Q |V| ZNT
            --------------------------------------
            output:     DCVM
        """
        result = ''
        #print("nuova posizione rotore num", str(rotore_num), Enigma.rotori[str(rotore_num)])

        for char in self.__encrypt:
            indice_alfabeto_std = ord(char) - ord('A')
            result += Enigma.rotori[str(rotore_num)][indice_alfabeto_std]
            
        return result


    def __str__(self):
        return f"{self.__encrypt}"



# turing machine code
class Bombe():
    alfabeto_nastro = {
        '0', 
        '1', 
        '_'
    }

    def __init__(self, msg_encrypt: str):
        self.__nastro = []

        # inserimento del messaggio criptato all'interno del nastro
        self.__nastro.append('_')
        for char in msg_encrypt:
            self.__nastro.append(char)
        self.__nastro.append('_')

        print(self.__nastro)

        # settings iniziali della macchina
        self.__testina          = 0

        self.__stato_corrente   = 0  # lo stato predefinito della macchina e' q0
        self.__stato_successivo = 1

        self.__simbolo_letto    = ""
        self.__simbolo_nuovo    = ""

        # impostato a True se deve andare a destra nel nastro, False se a sinistra
        self.__direzione        = "S" 


    def read_cells(self):
        self.__testina = 1
        
        while (self.__stato_corrente != "q_accept"):    

            if self.__nastro[self.__testina] == '_':
                self.__direzione = "D" if self.__direzione == "S" else "S" 

            if self.__direzione == "D": #la testina si sposta verso sinistra
                self.__testina -= 1
            else:
                self.__testina += 1
            
            self.__simbolo_letto = self.__nastro[self.__testina]

            self.__stato_corrente = self.update_new_stato()


    def update_new_stato(self):
        chiave = (self.__stato_corrente, self.__simbolo_letto)

        if chiave in self.__transizioni:
            stato_successivo, simbolo_nuovo, direzione = self.__transizioni[chiave]

            # Aggiorna il nastro
            self.__nastro[self.__testina] = simbolo_nuovo

            # Aggiorna la direzione
            self.__direzione = direzione

            return stato_successivo
        else:
            print("Errore: Transizione non definita.")
            return "q_error"


    def __str__(self):
        return f''



def main() -> int:
    text_example = "CIAO"
    msg_criptato = Enigma(text_example).__str__()

    Bombe(msg_criptato)
    return 0


if __name__ == "__main__":
    main()
