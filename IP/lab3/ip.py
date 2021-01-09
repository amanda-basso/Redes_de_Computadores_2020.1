from iputils import *
from ipaddress import ip_network, ip_address


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
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _busca_addr_em_cidr(self, addr, cidr, next_hop):
        if ip_address(addr) in ip_network(cidr):
            # Na primeira iteração
            if self.flag:
                print("1 Primeira iteracao")
                self.cidr_restritivo = cidr
                print(f"1 {self.cidr_restritivo}")
                self.next_hop = next_hop
                print(f"1 {self.next_hop}")
                self.flag = False
            else:
                print("2 Segunda iteracao")
                print(f"2 {self.cidr_restritivo}")
                print(f"2 {self.next_hop}")
                n_atual = cidr.split('/')[1]
                n_cidr_restritivo = self.cidr_restritivo.split('/')[1]
                if int(n_atual) > int(n_cidr_restritivo):
                    print(f"3 {n_atual}")
                    print(f"3 {n_cidr_restritivo}")
                    print("3 Atualiza")
                    self.cidr_restritivo = cidr
                    print(f"3 {self.cidr_restritivo}")
                    self.next_hop = next_hop
                    print(f"3 {self.next_hop}")



    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        # Passo 1: aqui, o next_hop só é considerado se o range do cidr incluir o destino
        for hop in self.tabela_encaminhamento:
            self._busca_addr_em_cidr(dest_addr, hop[0], hop[1])

        if self.next_hop != "":
            next_hop = self.next_hop
            self.next_hop = None
            self.cidr_restritivo = None
            self.flag = True
            print(f"4 {next_hop}")
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

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, next_hop)
