# Guia de Implementação no Servidor: Protocolo Multiplexado v2 (33/9 bytes)

Este documento detalha o passo a passo técnico e arquitetural para implementar o suporte ao protocolo binário multiplexado v2 no `dragontcp-server`.

---

## 1. Visão Geral da Mudança

No protocolo v1:
* **Requisição**: 29 bytes fixos (`[modo: 1B][SessionID: 16B][seq: 8B][len: 4B]`).
* **Resposta**: 5 bytes fixos (`[status: 1B][len: 4B]`).
* **Limitação**: Como a resposta não continha nenhum identificador, cada fluxo exigia conexões TCP físicas exclusivas (stop-and-wait).

No protocolo v2 (Multiplexado):
* **Requisição**: 33 bytes fixos (`[modo: 1B][SessionID: 16B][seq: 8B][request_id: 4B][len: 4B]`).
* **Resposta**: 9 bytes fixos (`[status: 1B][request_id: 4B][len: 4B]`).
* **Benefício**: Uma única conexão física TCP pode atender simultaneamente centenas de sessões lógicas, intercalando requisições e respostas de forma totalmente assíncrona.

```text
Cliente                                                   Servidor
  |                                                           |
  |--- Req [Seq: 0, ReqID: 1, Session: A] ------------------->|
  |--- Req [Seq: 0, ReqID: 2, Session: B] ------------------->|
  |                                                           |
  |<-- Resp [Status: OK, ReqID: 2, Body] (Session B) ---------|  (Processamento assíncrono)
  |<-- Resp [Status: OK, ReqID: 1, Body] (Session A) ---------|
```

---

## 2. Atualização do Pacote `internal/wire` no Servidor

O pacote `internal/wire` do servidor deve conter as mesmas definições implementadas no cliente:

```go
const (
	RequestHeaderSize     = 29
	ResponseHeaderSize    = 5
	MuxRequestHeaderSize  = 33
	MuxResponseHeaderSize = 9
	MaxPayload            = 2 * 1024 * 1024
)

type MuxRequest struct {
	Mode      byte
	Session   SessionID
	Seq       uint64
	RequestID uint32
	Payload   []byte
}

type MuxResponse struct {
	Status    byte
	RequestID uint32
	Body      []byte
}
```

### Leitura da Requisição v2 no Servidor:
```go
func ReadMuxRequestProfileEncoding(r io.Reader, headerMask byte, clear bool) (MuxRequest, error) {
	var req MuxRequest
	var header [MuxRequestHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return req, err
	}

	req.Mode = header[0] ^ headerMask
	if req.Mode > ModeClose {
		return req, errors.New("unknown request mode")
	}
	copy(req.Session[:], header[1:17])
	req.Seq = binary.BigEndian.Uint64(header[17:25])
	req.RequestID = binary.BigEndian.Uint32(header[25:29])
	n := binary.BigEndian.Uint32(header[29:33])
	if n > MaxPayload {
		return req, errors.New("request payload too large")
	}

	if n > 0 {
		req.Payload = make([]byte, int(n))
		if _, err := io.ReadFull(r, req.Payload); err != nil {
			return req, err
		}
		if !clear {
			MaskInPlace(req.Payload, req.Session, req.Mode, req.Seq, false)
		}
	}
	return req, nil
}
```

### Envio de Resposta v2 no Servidor:
```go
func WriteMuxResponseProfile(w io.Writer, status byte, reqID uint32, body []byte, headerMask byte) error {
	if len(body) > MaxPayload {
		return fmt.Errorf("response body too large: %d", len(body))
	}
	packet := make([]byte, MuxResponseHeaderSize+len(body))
	packet[0] = status ^ headerMask
	binary.BigEndian.PutUint32(packet[1:5], reqID)
	binary.BigEndian.PutUint32(packet[5:9], uint32(len(body)))
	copy(packet[9:], body)
	return writeAll(w, packet)
}

func WriteMaskedMuxResponseProfileEncoding(w io.Writer, status byte, reqID uint32, body []byte, sid SessionID, mode byte, seq uint64, headerMask byte, clear bool) error {
	if len(body) > MaxPayload {
		return fmt.Errorf("response body too large: %d", len(body))
	}
	if clear {
		var header [MuxResponseHeaderSize]byte
		header[0] = status ^ headerMask
		binary.BigEndian.PutUint32(header[1:5], reqID)
		binary.BigEndian.PutUint32(header[5:9], uint32(len(body)))
		buffers := net.Buffers{header[:], body}
		_, err := buffers.WriteTo(w)
		return err
	}
	packet := make([]byte, MuxResponseHeaderSize+len(body))
	packet[0] = status ^ headerMask
	binary.BigEndian.PutUint32(packet[1:5], reqID)
	binary.BigEndian.PutUint32(packet[5:9], uint32(len(body)))
	copy(packet[9:], body)
	MaskInPlace(packet[9:], sid, mode, seq, true)
	return writeAll(w, packet)
}
```

---

## 3. Negociação de Versão e Suporte Híbrido (v1 e v2)

Conforme a especificação (§13.1 e §13.4), o servidor deve aceitar tanto clientes legados (v1) quanto clientes atualizados (v2).

### Estratégia de Detecção
Ao receber uma nova conexão física TCP:
1. **Via Preface (`cover.Profile`)**: Se o preface de conexão trouxer o bit de capacidade `MultiplexV2: true` ou Profile ID correspondente, a conexão é marcada como multiplexada.
2. **Via Wire Sniffing (`sniffWire`)**: Se a negociação for direta, o sniffer identifica se o primeiro registro possui cabeçalho v1 (29 bytes) ou v2 (33 bytes).

---

## 4. Estrutura do Manipulador de Conexão no Servidor

Uma conexão física multiplexada **não pertence a apenas uma sessão**. Ela se comporta como um canal de transporte compartilhado (`muxTransport`):

```go
type muxServerConn struct {
	conn         net.Conn
	headerMask   byte
	clearPayload bool
	writeMu      sync.Mutex // Garante atomicidade na escrita de frames físicos
}

func (s *muxServerConn) sendResponse(status byte, reqID uint32, body []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return wire.WriteMuxResponseProfile(s.conn, status, reqID, body, s.headerMask)
}

func (s *muxServerConn) sendMaskedResponse(status byte, reqID uint32, body []byte, sid wire.SessionID, mode byte, seq uint64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return wire.WriteMaskedMuxResponseProfileEncoding(s.conn, status, reqID, body, sid, mode, seq, s.headerMask, s.clearPayload)
}
```

> [!IMPORTANT]
> **Atomicidade de Escrita**: Como várias goroutines podem responder requisições concorrentes na mesma conexão TCP, o `writeMu` é estritamente obrigatório. Sem ele, os bytes de respostas diferentes seriam corrompidos no socket.

---

## 5. Loop de Despacho de Requisições (`dispatchLoop`)

No servidor, uma única goroutine consome as requisições da conexão física e despacha a execução para goroutines assíncronas:

```go
func handleMuxConnection(mc *muxServerConn, manager *streamManager) {
	for {
		req, err := wire.ReadMuxRequestProfileEncoding(mc.conn, mc.headerMask, mc.clearPayload)
		if err != nil {
			return // Conexão fechada ou erro fatal de leitura
		}

		// Despacha o processamento de forma não-bloqueante
		go func(r wire.MuxRequest) {
			handleMuxRequest(mc, manager, r)
		}(req)
	}
}
```

---

## 6. Tratamento de Cada Modo Operacional

### 6.1 `ModeOpen` (Abertura de Sessão)
* O cliente envia `req.RequestID` junto com o payload contendo o destino (IP/Porta) e token.
* O servidor cria a sessão no `streamManager`.
* Resposta:
  ```go
  var body [4]byte
  binary.BigEndian.PutUint32(body[:], uint32(serverMaxChunk))
  mc.sendResponse(wire.StatusOK, req.RequestID, body[:])
  ```

### 6.2 `ModeUpload` (Envio de Dados pelo Cliente)
* O cliente envia dados com seu `RequestID` e `req.Seq` (offset absoluto).
* O servidor aplica o payload ao socket de destino através do método idempotente `writeUpload(req.Seq, req.Payload)`.
* **Garantia de Ordem**: Como o cliente envia uploads da mesma sessão em série, o servidor não precisa de buffer complexo de reordenamento.
* Resposta:
  ```go
  if err := session.writeUpload(req.Seq, req.Payload); err != nil {
      mc.sendResponse(wire.StatusError, req.RequestID, []byte(err.Error()))
      return
  }
  mc.sendResponse(wire.StatusOK, req.RequestID, nil)
  ```

### 6.3 `ModeDownload` (Batching de Download)
* O cliente solicita um lote de download especificando contagem e tamanho máximo de chunks.
* O servidor lê os bytes disponíveis do destino e transmite frames `StatusData`, todos carregando o **mesmo `RequestID`**.
* Ao terminar a leva de dados prontos (ou se a conexão fechar), o servidor emite o frame terminal (`StatusWait` ou `StatusEOF`) também com o **mesmo `RequestID`**:
  ```go
  offset := req.Seq
  for i := 0; i < count; i++ {
      data, eof, err := session.readChunk(maxChunk)
      if err != nil {
          mc.sendResponse(wire.StatusError, req.RequestID, []byte(err.Error()))
          return
      }
      if len(data) > 0 {
          mc.sendMaskedResponse(wire.StatusData, req.RequestID, data, req.Session, wire.ModeDownload, offset)
          offset += uint64(len(data))
      }
      if eof {
          mc.sendResponse(wire.StatusEOF, req.RequestID, nil)
          return
      }
      if len(data) == 0 {
          mc.sendResponse(wire.StatusWait, req.RequestID, nil)
          return
      }
  }
  // Se preencheu todo o batch com sucesso, encerra com Wait
  mc.sendResponse(wire.StatusWait, req.RequestID, nil)
  ```

### 6.4 `ModeClose` (Encerramento de Sessão)
* Fecha a sessão correspondente no `streamManager` e libera os sockets associados.
* Resposta:
  ```go
  manager.closeSession(req.Session)
  mc.sendResponse(wire.StatusOK, req.RequestID, nil)
  ```

### 6.5 `ModeProbe` (Calibração de Latência/Caminho)
* Usado para testes de sobrevivência e calibração de MTU/Path:
  ```go
  mc.sendResponse(wire.StatusOK, req.RequestID, nil)
  ```

---

## 7. Checklist de Validação no Servidor

- [ ] Sincronizar o pacote `internal/wire` com as constantes `MuxRequestHeaderSize (33)` e `MuxResponseHeaderSize (9)`.
- [ ] Garantir que o `writeMu` proteja qualquer chamada a `WriteMuxResponse*` na conexão TCP física.
- [ ] Garantir que **todas** as respostas a uma requisição (incluindo erros e frames de continuação de download) ecoem exatamente o mesmo `RequestID` recebido.
- [ ] Verificar se clientes v1 continuam funcionando normalmente na mesma porta via roteamento dinâmico ou flags de capability.
- [ ] Executar testes de estresse com múltiplas sessões SOCKS5 concorrentes para verificar ausência de travamentos ou concorrência na escrita de sockets.
