#########################################################
## funcao auxiliar
#########################################################

def print_dict_overview(d):
    print("\n===========================================================")
    # imprime chaves e valores do dicionário
    print("Dict:", d)
    print("\n-----------------------------------------------------------")
    print("Keys:", d.keys())
    print("Values:", d.values())
    print("\n-----------------------------------------------------------")

#########################################################
## Uma estrutura muito simples: dicionario, onde a chave é o switch
## Os valores, são listas de rotas, ou neste caso, tuples de tuples
#########################################################

alternative_paths_v1 = {1: ( 
                            ("192.168.1.10", 2, "192.168.4.10", 3, 1), 
                            ("192.168.4.10", 3, "192.168.1.10", 2, 1),
                            ),
                        2: (
                            ("192.168.1.10", 4, "192.168.4.10", 1, 1), 
                            ("192.168.4.10", 1, "192.168.1.10", 4, 1),
                            ),
                        5: (("192.168.1.10", 1, "192.168.4.10", 2, 1))
                      }

print_dict_overview(alternative_paths_v1)

# procura (id=2)

sw_id = 2
key = sw_id
# isto podia ser uma função de procura...
if (key in alternative_paths_v1 ):
    value = alternative_paths_v1[key]
    print("Chave (sw_id): ", key)
    print("Valor (tuple de tuples): ", value)
    print(" ---> Numero de rotas: ", len(value))
    # imprime a lista
    for r in value:
        print("      TUPLE")
        print("      =====")
        print("      IP origem: ", r[0])
        print("      Porta entrada: ", r[1])
        print("      IP destino: ", r[2])
        print("      Porta saida: ", r[3])
        print("      Prioridade: ", r[4])
else:
    print("Chave não existe! Chave: ", key)

sw_id = 7
key = sw_id
# isto podia ser uma função de procura...
if (key in alternative_paths_v1 ):
    value = alternative_paths_v1[key]
    print("Chave (sw_id): ", key)
    print("Valor (tuple de tuples): ", value)
    print(" ---> Numero de rotas: ", len(value))
    # imprime a lista
    for r in value:
        print("      TUPLE")
        print("      ====E")
        print("      IP origem: ", r[0])
        print("      Porta entrada: ", r[1])
        print("      IP destino: ", r[2])
        print("      Porta saida: ", r[3])
        print("      Prioridade: ", r[4])
else:
    print("Chave não existe! Chave: ", key)

#########################################################
## E se a chave fosse uma combinacao de valores?
## Um TUPLE (em python) com 
##  - sitch id, ip de origem, porta de entrda, ip de destino
########################################################

alternative_paths_v2 = {(1, "192.168.1.10", 2, "192.168.4.10"): (3, 1),
                      (2, "192.168.1.10", 4, "192.168.4.10"): (3, 1),
                      (3, "192.168.1.10", 1, "192.168.4.10"): (3, 1),
                      (5, "192.168.1.10", 1, "192.168.4.10"): (2, 1)
                      }

print_dict_overview(alternative_paths_v2)


# procura (id=3, src_ip=192.168.1.10, in_port=1, dst_ip=192.168.4.10)

sw_id = 3
src_ip = "192.168.1.10"
in_port = 1
dst_ip = "192.168.4.10"

key = (sw_id, src_ip, in_port, dst_ip)
# isto podia ser uma função de procura...
if (key in alternative_paths_v2 ):
    value = alternative_paths_v2[key]
    print("Chave (tuple): ", key)
    print(" ---> Id do switch: ", key[0])
    print(" ---> IP de origem: ", key[1])
    print(" ---> Porta de entrada: ", key[2])
    print(" ---> IP de destino: ", key[3])
    print("Valor (tuple): ", value)
    print(" ---> Porta de saida: ", value[0])
    print(" ---> Prioridade: ", value[1])
else:
    print("Chave não existe! Chave: ", key)

sw_id = 7
key = (sw_id, src_ip, in_port, dst_ip)
# isto podia ser uma função de procura...
if (key in alternative_paths_v2 ):
    value = alternative_paths_v2[key]
    print("Chave (tuple): ", key)
    print(" ---> Id do switch: ", key[0])
    print(" ---> IP de origem: ", key[1])
    print(" ---> Porta de entrada: ", key[2])
    print(" ---> IP de destino: ", key[3])
    print("Valor (tuple): ", value)
    print(" ---> Porta de saida: ", value[0])
    print(" ---> Prioridade: ", value[1])
else:
    print("Chave não existe! Chave: ", key)

