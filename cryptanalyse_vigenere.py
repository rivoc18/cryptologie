# Sorbonne Universit 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : NOM ET NUMERO D'ETUDIANT
# Etudiant.e 2 : NOM ET NUMERO D'ETUDIANT

import sys, getopt, string, math
from math import *

# Alphabet franais
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Frquence moyenne des lettres en franais
#  modifier
freq_FR = [0.09213437454330574,
           0.010354490059155806,
           0.030178992381545422,
           0.037536932666586184,
           0.17174754258773295,
           0.010939058717380115,
           0.0106150043524949,
           0.010717939268399616,
           0.07507259453174145,
           0.0038327371156619923,
           6.989407870073262e-05,
           0.06136827190067416,
           0.026498751437594118,
           0.07030835996721332,
           0.04914062053233872,
           0.023697905083841123,
           0.010160057440224678,
           0.06609311162084369,
           0.07816826681746844,
           0.0737433362349966,
           0.06356167517044624,
           0.016450524523290613,
           1.1437212878301701e-05,
           0.004071647784675406,
           0.0023001505899695645,
           0.0012263233808401269
           ]

# Chiffrement Csar
def chiffre_cesar(txt, key):
    s=""
    for i in txt:
        s+=chr(((ord(i)-65+key)%26)
        +65)
    return s

# Dchiffrement Csar
def dechiffre_cesar(txt, key):
    s=""
    for i in txt:
        s+=chr(((ord(i)-65-key)%26)+65)
    return s

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    Documentation   crire
    """
    s=""
    j=0
    for i in txt:
        #print(j)
        j=j%len(key)
        s+=chr(((ord(i)-65+key[j])%26)+65)
        j+=1
    #print(s)
    return s

# Dchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    s=""
    j=0
    for i in txt:
        #print(j)
        j=j%len(key)
        s+=chr(((ord(i)-65-key[j])%26)+65)
        j+=1
    #print(s)
    return s

# Analyse de frquences
def freq(txt):
    tab=[0.0]*26
    for i in txt:
        tab[ord(i)-65]+=1
    
    
    return tab

# Renvoie l'indice dans l'alphabet
# de la lettre la plus frquente d'un texte
def lettre_freq_max(txt):
    
    tab=freq(txt)
    max=0
    cpt=0
    for i in tab:
        if(i>tab[max]):
            max=cpt
        cpt+=1
    return max

# indice de concidence
def indice_coincidence(hist):
    s=0.0
    ttL=0
    for i in hist:
        ttL+=i
    for i in hist:
        s+=(i*(i-1))/(ttL*(ttL-1))
    return s


# Recherche la longueur de la cl
def longueur_clef(cipher):

    imcT=0
    for i in range(2,20):
        #print("la cle est",i)
        for j in range(i):
            colonne=cipher[j: :i]
            #print(colonne)
            imcT+=indice_coincidence(freq(colonne))
        imc=imcT/i
        if(imc>0.06):
            return i
        imcT=0
            

# Renvoie le tableau des dcalages probables tant
# donn la longueur de la cl
# en utilisant la lettre la plus frquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    
    decalages=[0]*key_length
    #print('decalage:',decalages)
    
    for j in range(key_length):
            colonne=cipher[j: :key_length]
            #print('colonne:',colonne)
            lettre=lettre_freq_max(colonne)
            decalages[j]=(lettre-4+26)%26
            #print (decalages[j])
    return decalages

# Cryptanalyse V1 avec dcalages par frequence max
def cryptanalyse_v1(cipher):

    newTexte=[]
    key_length=longueur_clef(cipher)
    decalages=clef_par_decalages(cipher,key_length)
    newTexte=dechiffre_vigenere(cipher,decalages)
    return newTexte
    #il y a 18 test qui reussie?
   #il est possible que les tests qui ont echoué sont des 
   #textes ou la lettre la plus frequente 
   #n'est pas le E, dut a un texte trop petit
################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec dcalage
def indice_coincidence_mutuelle(h1,h2,d):
    
    s=0.0
    s1=0.0
    for j in h1:
        s1+=j
    s2=0.0
    for k in h1:
        s2+=k
    for i in range(26):
        s+=h1[(i-d+26)%26]*h2[i]
    return s/(s1*s2)

# Renvoie le tableau des dcalages probables tant
# donn la longueur de la cl
# en comparant l'indice de dcalage mutuel par rapport
#   la premire colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Documentation   crire
    """
    decalages=[]
    max=0
    indice=0
    prems=cipher[0: :key_length]
    for j in range(key_length):
            colonne=cipher[j: :key_length]
            #print('colonne:',colonne)
            for d in range(26):
                imc=indice_coincidence_mutuelle(freq(prems),freq(colonne),d)
                if(max<imc):
                    max=imc
                    indice=d
            #print('indice',indice)
            decalages.append(indice)
            max=0
    #print('decalages',decalages)
    return decalages

# Cryptanalyse V2 avec dcalages par ICM
def cryptanalyse_v2(cipher):
    """
    """
    key_length=longueur_clef(cipher)
    decalages=tableau_decalages_ICM(cipher,key_length)
    texte=dechiffre_vigenere(cipher,decalages)
    cpt=0
    for i in range(26):
        if(((lettre_freq_max(texte)+cpt)%26)==4):
            #print('cpt',cpt)
            return chiffre_cesar(texte,cpt)
        else:
            cpt+=1
   #cyptanalyse_v2 a réussi à cryptanalyser 43 textes, 


            

    
    


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de mme taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    x=0.0
    y=0.0
    for i in range(len(L1)):
        x+=L1[i]
        y+=L2[i]
    x=x/len(L1)
    y=y/len(L2)
    a=0.0
    b=0.0
    c=0.0
    for j in range(len(L1)):
        a+=(L1[j]-x)*(L2[j]-y)
        b+=(L1[j]-x)*(L1[j]-x)
        c+=(L2[j]-y)*(L2[j]-y)
    
    s=a/(math.sqrt(b*c))
    #print(s)
    return s

# Renvoie la meilleur cl possible par correlation
# tant donn une longueur de cl fixe
def clef_correlations(cipher, key_length):
    key=[]
    score = 0.0
    corre_max=0.0
    max=0
    for j in range(key_length):
            colonne=cipher[j: :key_length]
            #print('colonne:',colonne)
            for i in range(26):
                colonne_decal=chiffre_cesar(colonne,i)
                if(corre_max<correlation(freq_FR,freq(colonne_decal))):
                        corre_max=correlation(freq_FR,freq(colonne_decal))
                        max=i
            #print('corre_max',corre_max)
            #print('colonne_max_corre',max)
            key.append((26-max)%26)
            max=0
            score+=corre_max
            corre_max=0
           
    score=score/key_length
    #print('score',score)
    #print('key',key)
                    
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    s=0
    cpt=0
    for i in range(1,20):
        cle=clef_correlations(cipher,i)
        if(cle[0]>s):
            s=cle[0]
            cpt=cle[1]
    txt=dechiffre_vigenere(cipher,cpt)
    return txt
#cyptanalyse_v3 a réussi à cryptanalyser 94 textes, il est possible que 
#la correlation est faussé dut a un trop petit texte


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN o N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
