from iputils import *
from ipaddress import ip_network, ip_address
import struct
import random

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        # Tabela de encaminhamento
        self.tabela_encaminhamento = []
        # Lista de cidrs que incluem o destino, para selecionar aquele que é mais restrito
        self.lista_cidr = []
        # Cidr mais restritivo
        self.cidr_restritivo = None
        # next hop associado ao cidr mais restritivo
        self.next_hop = None
        # Flag primeira iteracao
        self.flag = True

    # Passo 5: o segmento parametro da funcao é um um segmento falho
    def _cria_icmp(self, segmento, dest_addr):
        # Constroi o segmento do icmp
        header_icmp = struct.pack('!BBHI', 11, 0, 0, 0) + segmento[:28]
        header_icmp = header_icmp[:2] + struct.pack('!H', calc_checksum(header_icmp)) + header_icmp[4:]

        # Cria header
        header_icmp = self._cria_cabecalho(header_icmp, dest_addr, 1)

        return header_icmp

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # Passo 4: Trate corretamente o campo TTL do datagrama
            # Diminuir TTL, se for 0, retorna
            ttl -= 1
            if ttl == 0:
                icmp = self._cria_icmp(datagrama, src_addr)
                self.enlace.enviar(icmp, next_hop) # Retorna o segmento ip
                return
            # Substituir no header novo TTL
            datagrama = datagrama[:-12] + bytes([ttl]) + datagrama[-11:]
            datagrama = datagrama[:-10] + struct.pack('!H', 0) + datagrama[-8:]
            datagrama = datagrama[:-10] + struct.pack('!H',calc_checksum(datagrama)) + datagrama[-8:]
            # Recalcula checksum
            self.enlace.enviar(datagrama, next_hop)

    def _busca_addr_em_cidr(self, addr, cidr, next_hop):
        if ip_address(addr) in ip_network(cidr):
            # Na primeira iteração
            if self.flag:
                self.cidr_restritivo = cidr
                self.next_hop = next_hop
                self.flag = False
            else:
                n_atual = cidr.split('/')[1]
                n_cidr_restritivo = self.cidr_restritivo.split('/')[1]
                if int(n_atual) > int(n_cidr_restritivo):
                    self.cidr_restritivo = cidr
                    self.next_hop = next_hop


    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        # Passo 1: aqui, o next_hop só é considerado se o range do cidr incluir o destino
        for hop in self.tabela_encaminhamento:
            self._busca_addr_em_cidr(dest_addr, hop[0], hop[1])

        if self.next_hop != None:
            next_hop = self.next_hop
            self.next_hop = None
            self.cidr_restritivo = None
            self.flag = True
            return next_hop # Retorna cidr mais restritivo
        else:
            return None # Se não encontrou nada, retorna None

        pass

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        # Passo 1: tabela já está pronta
        self.tabela_encaminhamento = tabela

        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def _cria_cabecalho(self, conteudo, dest_addr, protocol):
        # Vai formando o cabecalho do IP
        # Aqui significa que o tamanho do header tem 20 bytes e que é ipv4 (01000101)
        src_address = self.meu_endereco
        dst_address = dest_addr

        # Concatena o header do IP
        header = struct.pack('!BBHHHBBH', 69, 0, 20 + len(conteudo), random.randint(0, 2000), 0, 64, protocol, 0)
        header = header + str2addr(src_address) + str2addr(dst_address)
        # Calculo + conserta checksum
        header = header[:-10] + struct.pack('!H',calc_checksum(header)) + header[-8:]

        # Retorna o header + segmento TCP
        return header + conteudo

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # Passo 2: cria o datagrama
        datagrama = self._cria_cabecalho(segmento, dest_addr, 6)

        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, next_hop)
