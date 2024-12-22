import re


class ADFGVX():
    SYMBOLS = ['A', 'D', 'F', 'G', 'V', 'X']

    # tabella che associa ogni elemento a una coppia di simboli presi dalla sequenza di ADFGVX.SYMBOLS
    POLIALFABETICA = [
        ["N", "A", "1", "C", "3", "H"],
        ["8", "T", "B", "2", "O", "M"],
        ["E", "5", "W", "R", "P", "D"],
        ["4", "F", "6", "G", "7", "I"],
        ["9", "J", "0", "K", "L", "Q"],
        ["S", "U", "V", "X", "Y", "Z"]
    ]

    def __init__(self, parola: str, key_word: str):
        # dalla stringa 'parola' devo togliere spazi, punteggiatura e i caratteri devono essere tutti upper:
        self.__parola       = re.sub(r"[^\w\d]*", "", parola.upper()) 

        self.__key          = key_word.upper()
        self.__first_step   = self.sostituzione()
        self.__second_step  = self.trasposizione()


    def sostituzione(self) -> str:
        """
            esempio con la parola "attack"

              | A	D	F	G	V	X
            --------------------------
            A | N	A	1	C	3	H
            D | 8	T	B	2	O	M
            F | E	5	W	R	P	D
            G | 4	F	6	G	7	I
            V | 9	J	0	K	L	Q
            X | S	U	V	X	Y	Z

            a -> AD
            t -> DD
            t -> DD
            a -> AD
            c -> AG
            k -> VG

            output del primo step sarà quindi:
            AD DD DD AD AG VG
        """
        parola_criptata = ''

        for carattere in self.__parola:
            x = 0
            y = 0

            for row in ADFGVX.POLIALFABETICA:
                if carattere in row:
                    x = row.index(carattere)
                    parola_criptata += (ADFGVX.SYMBOLS[y] + ADFGVX.SYMBOLS[x] + " ")
                    break
                y += 1  

        return parola_criptata


    def trasposizione(self) -> str:
        """
        Data una parola chiave, come "guerra" e come parola da cripatre "AD DD DD AD AG VG", bisogna ottenere la seguente struttura:
        
        G   U   E   R   R   A       -> parola chiave
        ----------------------
        A   D   D   D   D   A       -> ottenuta dal metodo sostituzione
        D   A   G   V   G

        Ora bisogna ordinare le colonne in base all'ordine alfabetico dei caratteri della parola GUERRA:

        A   E   G   R   R   U       -> caratteri ordinati secondo l'ordine alfabetico dal piu piccolo al piu grande
        ---------------------
        A   D   A   D   D   D
            G   D   V   G   A

        output della trasposizione sara: ADGADDVDGDA.
        """
        word = self.__first_step.replace(" ", "")
        keyword_length = len(self.__key)

        # il numero di colonne dipende dalla lunghezza della parola chiave
        columns = [''] * keyword_length

        # inserimento char x char nelle colonne
        for i, char in enumerate(word):
            columns[i % keyword_length] += char     


        # ordinamento delle colonne
        sorted_indices = sorted(
            range(keyword_length),          # elenco di indici che corrisponde al numero di colonne
            key=lambda k: self.__key[k]     # ogni indice e' ordinato in base al carattere della parola chiave corrispondente
        )

        # aggiungo il contenuto di ogni colonna all'interno di una stringa
        ciphertext = ''
        for column in sorted_indices:
            ciphertext += columns[column]

        return ciphertext


    def __str__(self) -> str:
        return f"{self.__second_step}"


def main() -> int:
    key = "privacy"
    
    f_inp = open("dante_canto_1.txt", "r", encoding = "UTF-8") # file di input
    f_out = open(f"{ADFGVX('dante_canto_1_encripted', key)}.txt", "w", encoding = "UTF-8") # file di output
    
    text = f_inp.read().split("\n")

    '''
    1 riga della lista = 1 riga del canto 
    text = [
        "row 1",
        "row 2",
        "row 3",
        etc...
    ]
    '''

    # eseguo l'algoritmo ADFGVX riga x riga del file di input
    line_counter = 1
    for line in text:
        result_encription = ADFGVX(line, key) 
        f_out.write(result_encription.__str__() + "\n") # scrivo la riga in output
        
        print(f"{line_counter}\t|", result_encription)
        line_counter += 1

    f_out.close()
    f_inp.close()
    return 0


if __name__ == "__main__":
    main()
