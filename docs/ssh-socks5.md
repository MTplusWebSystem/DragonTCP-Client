# Modo SSH + SOCKS5

Quando `--ssh-user` é definido, o DragonTCP Client opera em **modo de túnel SSH**. Em vez de (ou além do) proxy HTTP, ele abre uma conexão SSH através do transporte DragonTCP e expõe um proxy SOCKS5 completo em `--ssh-socks-host:--ssh-socks-port`.

---

## Arquitetura

```
Aplicativo Local (cliente SOCKS5)
    |
    v  SOCKS5 (TCP CONNECT ou UDP ASSOCIATE)
+---+----------------------------+
|   Proxy SOCKS5 (porta 1080)   |
|          |                    |
|   sshTunnelManager            |
|          |                    |
|   sshCarrierConn              |  <- buffer de coalescência de escritas
|          |                    |
|   Transporte Chunk DragonTCP  |  <- framing binário adaptativo
+---+----------+----------------+
    |          |
    v          v
 Tráfego TCP  Tráfego UDP
 (direct-tcpip) (via UDPGW)
    |
    v
Servidor SSH Remoto (dentro do servidor DragonTCP)
    |
    v
Host:Porta Alvo
```

---

## Gerenciador de Túnel SSH (`sshTunnelManager`)

O gerenciador mantém uma **única conexão persistente de cliente SSH** compartilhada entre todas as conexões SOCKS5.

### Ciclo de Vida da Conexão

1. `Warmup()` é chamado antes de o listener SOCKS5 iniciar — valida o caminho completo DragonTCP → SSH
2. Cada `DialTCP(host, porta)` abre um `ssh.Channel` do tipo `direct-tcpip`
3. Se a conexão SSH quebrar, ela é invalidada e reestabelecida no próximo dial
4. Uma goroutine de keepalive de 20 segundos envia requisições SSH `keepalive@dragontcp` para detectar conexões mortas

### SSH Carrier (`sshCarrierConn`)

A camada SSH emite pacotes criptografados em escritas relativamente pequenas (~dezenas de KiB). Sem coalescência, cada escrita SSH se torna uma transação completa request/response no DragonTCP, desperdiçando os grandes tamanhos de chunk encontrados pela calibração.

`sshCarrierConn` é um wrapper `net.Conn` que:
- Acumula escritas em até `maxBuffered` bytes (padrão: 4 MiB)
- Faz flush quando `flushBytes` (padrão: 1 MiB) estão acumulados OU após `flushDelay` (padrão: 2ms)
- Usa uma única goroutine escritora ordenada para drenar a fila
- Aplica contrapressão nos chamadores de `Write()` quando o buffer está cheio

Isso permite que muitos pacotes SSH pequenos sejam combinados em um único registro DragonTCP grande, utilizando totalmente o tamanho de chunk calibrado.

### Fixação de Chave do Host (Host Key Pinning)

Quando `--ssh-hostkey-pin-file` está definido:
- Na primeira conexão: o fingerprint SHA-256 é salvo no arquivo (TOFU — Trust On First Use)
- Nas conexões subsequentes: o fingerprint salvo é comparado; uma divergência retorna erro

---

## Proxy SOCKS5

O servidor SOCKS5 implementa o RFC 1928:

### Comandos Suportados

| Comando | Código | Descrição |
|---------|--------|-----------|
| CONNECT | 1 | Estabelece conexão TCP para o alvo via SSH `direct-tcpip` |
| UDP ASSOCIATE | 3 | Retransmite datagramas UDP via serviço UDPGW |

### Autenticação

Apenas **sem autenticação** (método 0x00) é suportado. O proxy rejeita clientes que não anunciam no-auth.

### Tipos de Endereço

| Tipo | Código | Suportado |
|------|--------|-----------|
| IPv4 | 1 | Sim |
| Domínio | 3 | Sim (para CONNECT); Não para UDP (prevenção de vazamento DNS) |
| IPv6 | 4 | Sim (apenas CONNECT; UDPGW é somente IPv4) |

---

## UDP Associate / UDPGW

UDP é retransmitido através de um serviço UDPGW no servidor DragonTCP. O protocolo UDPGW é um framing binário simples:

### Frame de Requisição UDPGW

```
Bytes 0-1:   PayloadLen (uint16 little-endian)
Bytes 2-3:   ConnectionID (uint16 big-endian)
Byte 4:      Flags
Bytes 5-8:   IPv4 de Destino
Bytes 9-10:  Porta de Destino (uint16 big-endian)
Bytes 11+:   Payload UDP
```

### Frame de Resposta UDPGW

```
Bytes 0-1:  PayloadLen (uint16 little-endian)
Bytes 2+:   Payload contendo:
  Bytes 0-2:  ConnectionID + flags (3 bytes)
  Bytes 3-6:  IPv4 de Origem
  Bytes 7-8:  Porta de Origem (uint16 big-endian)
  Bytes 9+:   Payload UDP
```

### Limitações do UDP

- Apenas destinos IPv4 são suportados
- Destinos com nome de domínio em datagramas UDP são rejeitados (prevenção de vazamento DNS)
- O cliente SOCKS5 deve usar endereços IP, não nomes de host, para UDP

---

## Exemplos de Configuração

```bash
# SSH + SOCKS5 básico
dragontcp-client \
  --server-host vpn.exemplo.com.br \
  --server-port 53 \
  --token s3cr3t \
  --ssh-user admin \
  --ssh-password minha_senha \
  --ssh-socks-host 127.0.0.1 \
  --ssh-socks-port 1080

# Com fixação de chave do host
dragontcp-client \
  --server-host vpn.exemplo.com.br \
  --server-port 53 \
  --token s3cr3t \
  --ssh-user admin \
  --ssh-password minha_senha \
  --ssh-hostkey-pin-file ~/.dragontcp/hostkey.pin \
  --ssh-socks-port 1080

# Senha via variável de ambiente
SSH_PASS=minha_senha dragontcp-client \
  --server-host vpn.exemplo.com.br \
  --server-port 53 \
  --token s3cr3t \
  --ssh-user admin \
  --ssh-password-env SSH_PASS \
  --ssh-socks-port 1080
```

---

## Mensagens de Log

```
ssh carrier: opening DragonTCP stream to dragontcp-ssh.internal:2222
ssh carrier: DragonTCP stream connected write_batch=1048576 max_buffer=4194304 ...
ssh authenticated: user=admin transport=DragonTCP mode=tunnel-only
ssh host key pinned: SHA256:xxxx...
ssh carrier: packet coalescing active batch=262144
ssh traffic: direct-tcpip active
ssh traffic: UDPGW active target=dragontcp-udpgw.internal:7400
ssh_mode=true local_socks5=127.0.0.1:1080 internal_ssh=dragontcp-ssh.internal:2222 ...
```
