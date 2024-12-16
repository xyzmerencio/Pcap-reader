from scapy.all import *
import argparse

# Argumentos da linha de comando
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pcap-file", action="store", required=True, dest="pcap", help="Arquivo PCAP para analisar")
parser.add_argument("-f", "--display-filter", action="store", required=False, dest="s_filter", help="Filtro de camada para usar no Scapy (opcional)")
args = parser.parse_args()

# Define o arquivo PCAP e o filtro fornecidos pelo usuário
pcap = args.pcap
s_filter = args.s_filter

# Lê o arquivo PCAP
packets = rdpcap(pcap)

# Itera por todos os pacotes no arquivo
for packet in packets:
    # Se um filtro foi especificado, verifica se o pacote possui a camada correspondente
    if s_filter:
        if packet.haslayer(s_filter):  # Verifica se o pacote contém a camada especificada no filtro
            packet.display()  # Exibe os detalhes do pacote
            input("Pressione Enter para continuar")  # Pausa para o usuário analisar o pacote
    else:
        # Se nenhum filtro for especificado, exibe todos os pacotes
        packet.display()
