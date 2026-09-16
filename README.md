# DragonTCP Client

> **Proxy TCP adaptativo binário** — tuneliza tráfego HTTP/HTTPS através de um servidor DragonTCP usando um protocolo de framing auto-calibrável, projetado para sobreviver a redes restritivas (porta 53, firewalls corporativos, NATs móveis).

---

## Sumário

- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Transportes e Modos de Wire](#transportes-e-modos-de-wire)
- [Primeiros Passos](#primeiros-passos)
  - [Pré-requisitos](#pré-requisitos)
  - [Compilar para Desktop](#compilar-para-desktop-linuxmacoswindows)
  - [Compilar para Android](#compilar-para-android)
- [Uso](#uso)
  - [Modo Proxy HTTP Básico](#modo-proxy-http-básico)
  - [Varredura de Faixa de Portas](#varredura-de-faixa-de-portas)
  - [Modo SSH + SOCKS5](#modo-ssh--socks5)
  - [Payload HTTP Personalizado](#payload-http-personalizado-injeção-snihttp)
- [Referência de Flags da CLI](#referência-de-flags-da-cli)
- [Sequência de Inicialização](#sequência-de-inicialização)
- [Pacotes Internos](#pacotes-internos)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Testes](#testes)

---

## Visão Geral

O DragonTCP Client é uma aplicação Go que atua como **proxy HTTP local** (e opcionalmente proxy SOCKS5 via SSH). O tráfego das aplicações locais é tunelizado através de um servidor DragonTCP remoto usando um protocolo de framing binário proprietário, otimizado para:

- **Sobrevivência em carriers** — detecta automaticamente qual formato de wire e máscara de cabeçalho a rede permite
- **Chunk size adaptativo** — calibra o tamanho dos registros de upload/download em tempo real com base nos limites do carrier
- **Suporte multi-wire** — seleciona entre `b` (binário), `bp` (pipelined bidirecional) e `x` (XOR legado)
- **SSH + SOCKS5** — modo SSH opcional que expõe um proxy SOCKS5 completo com TCP + UDP (via UDPGW)

O cliente é compilado como **biblioteca compartilhada (`.so`)** para Android (`buildmode=pie`) e como binário nativo para plataformas desktop.

---

## Arquitetura

```
+----------------------------------------------------------+
|               Aplicação Local                            |
|  (Navegador, VPN Android, etc.)                          |
+------------------------+---------------------------------+
                         | HTTP CONNECT / HTTP simples
                         v
+----------------------------------------------------------+
|       DragonTCP Client (Proxy HTTP Local)                |
|  listen-host:listen-port  (padrão: 127.0.0.1:8080)      |
|                                                          |
|  +--------------+  +---------------+  +---------------+  |
|  | Parser HTTP  |->| Seletor Wire  |->| Chunk Tunnel  |  |
|  | (CONNECT /   |  | (auto/b/bp/x) |  | (UL/DL adapt. |  |
|  |  GET simples)|  |               |  |  por sessão)  |  |
|  +--------------+  +-------+-------+  +---------------+  |
|                            | (opcional)                  |
|                    +-------v-------+                     |
|                    | Túnel SSH +   |                     |
|                    | Proxy SOCKS5  |                     |
|                    | (UDPGW)       |                     |
|                    +---------------+                     |
+-----------------------------------+---------------------+
                                    | Framing binário DragonTCP
                                    | (TCP, porta padrão 53)
                                    v
+----------------------------------------------------------+
|              Servidor DragonTCP Remoto                   |
+----------------------------------------------------------+
```

---

## Transportes e Modos de Wire

| Modo   | Flag          | Descrição |
|--------|---------------|-----------|
| `b`    | `--wire b`    | **Binário** — cabeçalhos compactos de 29/5 bytes, payloads mascarados com SHA-256 |
| `bp`   | `--wire bp`   | **Binário Pipelined** — sessões bidirecionais com lanes separados de upload/download, downloads em lote |
| `x`    | `--wire x`    | **XOR Legado** — framing `UP`/`OK` de 14/10 bytes, mascaramento XOR 0xAD |
| `auto` | `--wire auto` | **Detecção automática** — sonda 160 candidatos de máscara e escolhe o primeiro que sobrevive ao carrier |

### Algoritmo de Seleção de Wire

1. Na inicialização, `wireSelector.resolveOnly()` envia uma sonda local mínima para cada candidato (máscara × família de wire)
2. O primeiro perfil validado é **armazenado em cache pelo tempo de vida do processo** — todas as conexões subsequentes o reutilizam
3. A varredura por faixa de portas executa verificação de alcançabilidade TCP + validação de protocolo antes de aceitar qualquer porta
4. Após a seleção do wire, a calibração UP/DW encontra o tamanho máximo seguro de payload para o carrier

### Cover Preface

Cada conexão TCP física pode iniciar com um **preface de cobertura** de 12 bytes + padding (magic `DTC3`, chaveado com SHA-256). O preface informa ao servidor:
- Qual máscara de cabeçalho esperar
- Se os payloads estão mascarados com SHA-256 ou limpos (`--force-clear-payload`)
- Tamanho de padding aleatório opcional (modelagem de tráfego)

---

## Primeiros Passos

### Pré-requisitos

- **Go 1.26+** (ver `go.mod`)
- Para builds Android: **Android NDK 30** (detectado automaticamente via `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, ou `%LOCALAPPDATA%\Android\Sdk\ndk\`)

### Compilar para Desktop (Linux/macOS/Windows)

```bash
go build -o dragontcp-client .
```

### Compilar para Android

Use o script PowerShell (Windows):

```powershell
# Padrão: arm64-v8a
.\build.ps1

# Todas as 4 arquiteturas ABI
.\build.ps1 -Abi all

# Caminho do NDK personalizado
.\build.ps1 -NdkPath "C:\caminho\para\ndk\30.x" -Abi arm64-v8a
```

Arquivos gerados:
```
builds/
+-- arm64-v8a/
|   +-- libdragontcp_client.so      <- caminho compatível com jniLibs
+-- libdragontcp_client-arm64-v8a.so
+-- libdragontcp_client.so          <- cópia principal
```

O script também sincroniza automaticamente para `android/lib/<ABI>/` se o diretório existir.

---

## Uso

### Modo Proxy HTTP Básico

```bash
dragontcp-client \
  --server-host example.com \
  --server-port 53 \
  --token meutoken \
  --listen-host 127.0.0.1 \
  --listen-port 8080
```

Configure seu navegador/aplicativo para usar `127.0.0.1:8080` como proxy HTTP.

### Varredura de Faixa de Portas

```bash
dragontcp-client \
  --server-host example.com \
  --server-port-start 53 \
  --server-port-end 8053 \
  --token meutoken
```

Varre as portas 53–8053 e bloqueia na primeira que passa a sonda de protocolo DragonTCP.

### Modo SSH + SOCKS5

```bash
dragontcp-client \
  --server-host example.com \
  --server-port 53 \
  --token meutoken \
  --ssh-user admin \
  --ssh-password senha123 \
  --ssh-socks-host 127.0.0.1 \
  --ssh-socks-port 1080
```

Configure seu aplicativo para usar SOCKS5 em `127.0.0.1:1080`. UDP é suportado via UDPGW.

### Payload HTTP Personalizado (Injeção SNI/HTTP)

```bash
dragontcp-client \
  --server-host example.com \
  --server-port 80 \
  --http-payload "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf][crlf]"
```

Tokens de template disponíveis: `[crlf]`, `[lf]`, `[cr]`, `[host]`, `[port]`, `[host_port]`, `[protocol]`, `[ua]`

---

## Referência de Flags da CLI

### Básicas

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--listen-host` | `127.0.0.1` | Host de escuta do proxy local |
| `--listen-port` | `8080` | Porta de escuta do proxy local |
| `--server-host` | *(obrigatório)* | Hostname ou IP do servidor DragonTCP remoto |
| `--server-port` | `53` | Porta do servidor (sem faixa) |
| `--server-port-start` | `0` | Início da faixa de varredura (0 = usa `--server-port`) |
| `--server-port-end` | `0` | Fim da faixa de varredura (0 = igual ao início) |
| `--token` | `""` | Token de autenticação compartilhado |
| `--max-connections` | `20000` | Máximo de conexões proxy simultâneas |
| `--tcp-buffer` | `0` | Tamanho do buffer TCP em bytes (0 = autotuning do SO) |
| `--http-payload` | `""` | Payload HTTP personalizado injetado antes do framing binário |

### Wire / Protocolo

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--wire` | `auto` | Modo wire: `b`, `bp`, `x` ou `auto` |
| `--wire-probe-delay` | `100ms` | Atraso mínimo entre tentativas de sonda de perfil |
| `--wire-probe-threads` | `1` | Máximo de sondas de perfil concorrentes (1–16) |
| `--force-clear-payload` | `false` | Desabilita mascaramento SHA-256 do payload |
| `--protocol-version` | `v1` | `v1` (29/5 bytes) ou `v2` (33/9 bytes, multiplexado) |

### Ajuste de Chunks

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--chunk-start` | `1048576` | Tamanho inicial do chunk em bytes |
| `--chunk-min` | `32` | Tamanho mínimo do chunk |
| `--chunk-max` | `1048576` | Tamanho máximo (limite fixo: 1 MiB) |
| `--chunk-adaptive` | `true` | Habilita adaptação automática do tamanho |
| `--chunk-grow-after` | `16` | Sucessos necessários para aumentar |
| `--chunk-shrink-after` | `1` | Falhas consecutivas para reduzir |
| `--chunk-shrink-step` | `200` | Bytes subtraídos por falha |
| `--chunk-max-first` | `false` | Calibração max-first legada (somente CLI) |
| `--chunk-adapt-log` | `true` | Registra mudanças de tamanho de chunk |
| `--chunk-concurrency` | `1` | Máx. de registros de download por requisição (1–256) |
| `--chunk-concurrency-min` | `1` | Profundidade mínima do pipeline de download |
| `--chunk-reconnect-every` | `0` | 0=persistente, 1=auto-aprender, N=rotacionar a cada N requisições |
| `--chunk-poll-delay` | `2ms` | Atraso após sondagem vazia do servidor |
| `--chunk-timeout` | `5s` | Timeout de transação por registro |

### SSH / SOCKS5

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--ssh-user` | `""` | Usuário SSH (habilita modo SSH+SOCKS5) |
| `--ssh-password` | `""` | Senha SSH |
| `--ssh-password-env` | `""` | Variável de ambiente com a senha SSH |
| `--ssh-internal-host` | `dragontcp-ssh.internal` | Alvo DragonTCP reservado para SSH interno |
| `--ssh-internal-port` | `2222` | Porta SSH interna no servidor DragonTCP |
| `--ssh-hostkey-pin-file` | `""` | Arquivo de fingerprint SSH (TOFU) |
| `--ssh-socks-host` | `127.0.0.1` | Host de escuta do proxy SOCKS5 local |
| `--ssh-socks-port` | `1080` | Porta de escuta do proxy SOCKS5 local |
| `--ssh-udpgw-host` | `dragontcp-udpgw.internal` | Alvo UDPGW visto pelo servidor SSH |
| `--ssh-udpgw-port` | `7400` | Porta UDPGW |

### Fake iPerf (Teste de Throughput)

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--iperf-duration` | `0` | Duração do teste sustentado (ex: `15s`; 0 = desabilitado) |
| `--iperf-target-mbps` | `1.0` | Throughput agregado alvo em Mbps |

---

## Sequência de Inicialização

```
1. PARSE E VALIDAÇÃO DE FLAGS
       |
       v
2. VARREDURA DE PORTAS  [phase=PORT_SCAN]
   +-- Verificação de alcançabilidade TCP (timeout escala com candidatos)
   +-- Sonda de protocolo (wireSelector.resolveOnly)
         => confirma que o framing DragonTCP sobrevive ao carrier
       |
       v
3. AUTENTICAÇÃO WIRE  [phase=AUTH]
   +-- Valida o perfil wire/máscara escolhido na varredura
       |
       v
4. CALIBRAÇÃO  [phase=CALIBRATION]
   +-- Sonda de upload   => tamanho máximo seguro de chunk UL
   +-- Sonda de download => tamanho máximo seguro de chunk DL
   (Opcional: teste fake-iperf sustentado se --iperf-duration > 0)
       |
       v
5. AQUECIMENTO SSH  (se --ssh-user definido)
   +-- Handshake completo DragonTCP -> SSH antes de anunciar o SOCKS5
       |
       v
6. PROXY ATIVO  [phase=ACTIVE]
   +-- Proxy HTTP em listen-host:listen-port
   +-- Proxy SOCKS5 em ssh-socks-host:ssh-socks-port (somente modo SSH)
```

---

## Pacotes Internos

### `internal/protocol`

Camada de framing central para o transporte XOR legado e utilitários TCP.

| Símbolo | Descrição |
|---------|-----------|
| `WriteRequestFrame` | Codifica magic `UP` + payload mascarado com XOR |
| `ReadResponseFrame` | Decodifica magic `OK` + resposta mascarada com XOR |
| `RelayRaw` / `RelayXOR` | Relay TCP bidirecional |
| `TuneTCP` / `TuneTCPBuffer` | Define `TCP_NODELAY`, keepalive e buffers de socket |
| `DialTCP` | Conecta com injeção opcional de payload HTTP |
| `FormatPayload` | Substituição de templates para `--http-payload` |
| `XorInPlace` | Mascaramento XOR 0xAD de payload (otimizado SIMD 32/64-bit) |

### `internal/wire`

Framing binário para os transportes `b` e `bp`.

| Símbolo | Descrição |
|---------|-----------|
| `WriteRequestProfileEncoding` | Requisição de 29 bytes (ou 33 bytes mux) com payload SHA-256 ou limpo |
| `ReadResponseProfile` | Decodificador de cabeçalho de resposta de 5 bytes (ou 9 bytes mux) |
| `MaskInPlace` | Mascaramento de payload em modo contador SHA-256 |
| `DecodeMaskedResponse` | Desmascara resposta in-place |
| `SessionID` | Identificador de sessão aleatório de 16 bytes |
| `RequestIDPool` | Pool com lista livre de IDs para requisições multiplexadas |

### `internal/cover`

Preface TCP opcional para descoberta de perfil de carrier.

| Símbolo | Descrição |
|---------|-----------|
| `Profile` | Configuração do preface (ID, padding, máscara, flag XOR, flag clear) |
| `EncodePreface` / `DecodePreface` | Codificação/decodificação do preface fixo de 12 bytes |
| `WritePreface` | Envia preface + bytes de padding aleatórios em nova conexão |

### `internal/xorchunk`

Lógica de chunk e calibração para o transporte XOR (wire `x` legado).

| Símbolo | Descrição |
|---------|-----------|
| `Options` | Configuração de chunk para o transporte XOR |
| `Calibrate` | Calibração de tamanho de chunk UP/DW |
| `Open` | Abre uma sessão usando framing XOR |
| `ProbeProfile` | Sonda de perfil de cabeçalho para o wire X |

---

## Estrutura do Projeto

```
dragontcp-client/
+-- main.go                  # Ponto de entrada: proxy HTTP, varredura de portas, parse de flags
+-- chunk.go                 # Transporte binário: sizer adaptativo, request lanes, sondas iPerf
+-- bp.go                    # Wire BP: sessão pipelined bidirecional (bpConn)
+-- wireselect.go            # Seletor de wire: auto-detecção, sonda de perfil, despacho de dial
+-- ssh_tunnel.go            # Gerenciador de túnel SSH + loop de keepalive de 20s
+-- ssh_carrier.go           # Wrapper net.Conn com coalescência de escritas para SSH sobre DragonTCP
+-- socks5.go                # Proxy SOCKS5 (TCP CONNECT + UDP ASSOCIATE / UDPGW)
+-- transport_error.go       # Helper isTransportTimeout
+-- go.mod                   # Módulo: dragontcp, Go 1.26+, golang.org/x/crypto
+-- build.ps1                # Script de cross-compilação Android NDK (PowerShell)
+-- builds/                  # Bibliotecas compartilhadas Android compiladas
|   +-- arm64-v8a/
|       +-- libdragontcp_client.so
+-- docs/                    # Documentação técnica aprofundada
+-- internal/
    +-- cover/
    |   +-- profile.go       # Preface de cobertura TCP (magic DTC3)
    +-- protocol/
    |   +-- protocol.go      # Framing XOR, relay, tuning TCP, injeção de payload
    |   +-- xor_fast32.go    # XOR SIMD 32-bit
    |   +-- xor_fast64.go    # XOR SIMD 64-bit
    |   +-- xor_generic.go   # XOR genérico (fallback)
    +-- wire/
    |   +-- protocol.go      # Framing wire binário (B/BP, mux v1/v2, máscara SHA-256)
    +-- xorchunk/
        +-- chunk.go         # Lógica e calibração de chunk XOR
```

---

## Testes

```bash
# Executar todos os testes
go test ./...

# Saída detalhada
go test -v ./...

# Pacotes específicos
go test -v ./internal/wire/...
go test -v ./internal/cover/...
go test -v ./internal/xorchunk/...

# Casos de teste específicos
go test -v -run TestChunk .
go test -v -run TestWireSelect .
go test -v -run TestSOCKS .
go test -v -run TestSSH .
```

Principais arquivos de teste:

| Arquivo | Cobertura |
|---------|-----------|
| `chunk_test.go` | Sizer adaptativo, lógica de sonda, iPerf |
| `wireselect_test.go` | Detecção de wire, candidatos de perfil, validação de máscara |
| `socks5_test.go` | Negociação do protocolo SOCKS5 |
| `ssh_tunnel_test.go` | Gerenciador de túnel SSH |
| `ssh_carrier_test.go` | Coalescência de escritas |
| `transport_error_test.go` | Detecção de timeout |
| `internal/wire/protocol_test.go` | Round-trips de framing binário |
| `internal/xorchunk/chunk_test.go` | Lógica de chunk XOR |
| `internal/cover/profile_test.go` | Codificação/decodificação do preface |
