# Referência do Protocolo Wire DragonTCP

Este documento descreve os formatos de framing binário usados pelo cliente DragonTCP.

---

## Versões do Protocolo

| Versão | Cabeçalho de Requisição | Cabeçalho de Resposta | Uso |
|--------|------------------------|-----------------------|-----|
| v1     | 29 bytes                | 5 bytes                | Padrão; sessão única por conexão |
| v2 (Mux) | 33 bytes             | 9 bytes                | Multiplexado; carrega um RequestID adicional de 4 bytes |

---

## Conceitos Comuns

### SessionID

Identificador aleatório criptograficamente seguro de 16 bytes, atribuído na abertura da sessão. Usado como semente para o mascaramento de payload com SHA-256.

### Máscara de Cabeçalho (Header Mask)

Um único byte XORead com o primeiro byte de cada cabeçalho de requisição e resposta. Selecionado durante a descoberta de perfil wire na inicialização. Máscaras B/BP válidas têm os 3 bits menos significativos zerados (`mask & 0x07 == 0`), resultando em 32 valores possíveis (0x00, 0x08, 0x10, ..., 0xF8). Máscaras X válidas satisfazem `('U' ^ mask) & 0x07 >= 5`, resultando em 96 valores.

### Mascaramento de Payload SHA-256

Payloads são mascarados em modo contador:

```
semente = SessionID(16) || Mode(1) || Seq(8) || Direcao(1) || Contador(4)
bloco_chave = SHA256(semente)
ciphertext[i] ^= bloco_chave[i % 32]
```

Quando `--force-clear-payload` está definido (ou o preface de cobertura anuncia `Clear=true`), o payload é enviado sem mascaramento.

---

## Wire B — Transporte Binário

### Frame de Requisição (29 bytes + payload)

```
Byte 0:      Mode ^ headerMask
Bytes 1-16:  SessionID (16 bytes)
Bytes 17-24: Seq (uint64 big-endian)
Bytes 25-28: PayloadLen (uint32 big-endian)
Bytes 29+:   Payload (mascarado SHA-256 ou limpo)
```

**Valores de Mode:**

| Valor | Nome | Descrição |
|-------|------|-----------|
| 0 | Probe | Sonda local do servidor (calibração/keepalive) |
| 1 | Open | Abre um túnel para host:porta alvo |
| 2 | Upload | Envia dados para a sessão |
| 3 | Download | Solicita dados ao servidor |
| 4 | Close | Fecha a sessão |

### Frame de Resposta (5 bytes + corpo)

```
Byte 0:    Status ^ headerMask
Bytes 1-4: BodyLen (uint32 big-endian)
Bytes 5+:  Corpo (mascarado SHA-256 ou limpo)
```

**Valores de Status:**

| Valor | Nome | Descrição |
|-------|------|-----------|
| 0 | OK | Sucesso; sem corpo ou corpo de ACK |
| 1 | Error | Erro do servidor; corpo é mensagem de erro UTF-8 |
| 2 | Data | Resposta contém bytes de dados |
| 3 | Wait | Servidor sem dados; cliente deve tentar novamente |
| 4 | EOF | Stream encerrado; sem mais dados |

---

## Wire BP — Transporte Binário Pipelined

BP reutiliza o mesmo cabeçalho de 29 bytes de requisição e 5 bytes de resposta, mas adiciona gerenciamento de ciclo de vida de sessão:

### Ciclo de Vida da Sessão

```
Cliente                          Servidor
  |                                 |
  |-- UPLOAD(seq=0, nil) ---------->|  Registro
  |<-- OK --------------------------|
  |-- UPLOAD(seq=1, OPEN_MAGIC+alvo)->| Abre alvo
  |<-- OK --------------------------|
  |                                 |
  |-- UPLOAD(seq=2+, dados) ------->|  Envia dados
  |<-- OK --------------------------|
  |                                 |
  |-- DOWNLOAD(hint=chunkSize) ---->|  Sonda download
  |<-- DATA / WAIT / EOF -----------|
  |                                 |
  |-- ACK(seq=consumido) ---------->|  Confirma bytes consumidos
  |<-- OK --------------------------|
  |                                 |
  |-- ACK(CLOSE_MAGIC) ------------>|  Fecha sessão
```

**Magic de Abertura:** `D O P 1` (0x44 0x4F 0x50 0x31)
**Magic de Fechamento:** `D C L 1` (0x44 0x43 0x4C 0x31)

### Download em Lote (Batch Download)

Quando `--chunk-concurrency > 1`, BP usa `bpModeBatchDownload` (modo 3). O payload da requisição carrega:
```
Bytes 0-3: MaxChunk (uint32 big-endian)
Bytes 4-5: Count (uint16 big-endian)
```
O servidor responde com `Count` respostas individuais DATA/WAIT/EOF.

---

## Wire Multiplexado (v2)

O protocolo v2 adiciona um campo `RequestID` de 4 bytes em ambos os cabeçalhos de requisição e resposta, permitindo múltiplas requisições em voo sobre uma única conexão.

### Frame de Requisição Mux (33 bytes + payload)

```
Byte 0:      Mode ^ headerMask
Bytes 1-16:  SessionID
Bytes 17-24: Seq (uint64 big-endian)
Bytes 25-28: RequestID (uint32 big-endian)
Bytes 29-32: PayloadLen (uint32 big-endian)
Bytes 33+:   Payload (mascarado ou limpo)
```

### Frame de Resposta Mux (9 bytes + corpo)

```
Byte 0:    Status ^ headerMask
Bytes 1-4: RequestID (uint32 big-endian)
Bytes 5-8: BodyLen (uint32 big-endian)
Bytes 9+:  Corpo (mascarado ou limpo)
```

---

## Wire X — Transporte XOR Legado

O transporte legado usa magic ASCII `UP`/`OK` com mascaramento XOR 0xAD.

### Frame de Requisição (14 bytes + payload)

```
Byte 0:      'U' ^ headerMask
Byte 1:      'P' ^ headerMask
Bytes 2-5:   RequestID (uint32 big-endian)
Bytes 6-9:   Reservado (4 bytes, zeros)
Bytes 10-13: PayloadLen (uint32 big-endian)
Bytes 14+:   Payload (mascarado XOR 0xAD)
```

### Frame de Resposta (10 bytes + payload)

```
Byte 0:    'O' ^ headerMask
Byte 1:    'K' ^ headerMask
Bytes 2-5: RequestID (uint32 big-endian)
Bytes 6-9: PayloadLen (uint32 big-endian)
Bytes 10+: Payload (mascarado XOR 0xAD)
```

### Comando de Túnel

```
TUNNEL <token> <host> <porta>        # modo XOR
TUNNEL2 <token> <host> <porta> RAW  # modo Raw (sem XOR no relay de payload)
```

---

## Cover Preface

Preface opcional de 12 bytes + padding enviado no início de cada nova conexão TCP quando a descoberta de perfil está ativa.

### Layout do Preface (12 bytes)

```
Bytes 0-1:   ID do Perfil (uint16 big-endian) — público, sem máscara
Bytes 2-11:  Metadados mascarados (10 bytes, XOR com SHA-256(semente))
```

### Metadados Mascarados (texto plano, antes do mascaramento)

```
Bytes 0-3: Magic "DTC3"
Byte 4:    Flags (bit0=XOR, bit1=Clear)
Byte 5:    HeaderMask
Bytes 6-7: Comprimento do padding (uint16 big-endian)
Byte 8:    Checksum: Byte4 ^ Byte5 ^ 0xA5
Byte 9:    Checksum: Byte6 ^ Byte7 ^ 0x5A
```

Após o preface de 12 bytes, exatamente `Padding` bytes de dados aleatórios criptográficos são enviados (modelagem de tráfego / resistência a fingerprinting).

### Derivação de Chave

```
semente = "DragonTCP-C3" || ProfileID(big-endian) || ID_byte0^0x6D || ID_byte1^0xB2
chave   = SHA256(semente)
```

---

## Protocolo de Sonda

Sondas validam que uma combinação wire/máscara sobrevive ao carrier. São locais ao servidor: o servidor não abre nenhuma conexão externa.

### Magic de Sonda

`D T P 2` (0x44 0x54 0x50 0x32)

### Layout do Payload de Sonda

```
Bytes 0-3:  ProbeMagic ("DTP2")
Byte 4:     ProbeKind (tipo de sonda)
Bytes 5-6:  TokenLen (uint16 big-endian)
Bytes 7-10: Value (uint32 big-endian)
Bytes 11+:  Token || padrão de padding ((i*31+17) & 0xff)
```

**Tipos de sonda:**

| Valor | Nome | Descrição |
|-------|------|-----------|
| 1 | ProbeUpload | Valida caminho de upload; tamanho do payload = Value |
| 2 | ProbeDownload | Valida caminho de download; servidor ecoa `Value` bytes |
| 3 | ProbeKeepalive | Round-trip simples; servidor responde OK |
| 4 | ProbeBatch | Sonda em lote (reservado) |
| 5 | ProbeIperfUpload | Sonda iPerf de upload sustentado |
| 6 | ProbeIperfDownload | Sonda iPerf de download sustentado |
