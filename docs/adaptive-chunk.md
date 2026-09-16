# Calibração Adaptativa de Chunks

Este documento descreve como o DragonTCP Client descobre o tamanho máximo seguro de registro de payload para um determinado carrier e como o adapta em tempo de execução.

---

## Por que Chunks Adaptativos?

Redes móveis e corporativas frequentemente impõem limites invisíveis de bytes em segmentos de payload TCP — especialmente na porta 53, onde tráfego DNS é esperado. Um payload 1 byte acima do limite do carrier causa um descarte silencioso, timeout ou reset TCP. TLS/HTTP padrão não tem esse problema por serem protocolos de stream com retransmissão automática; o DragonTCP usa registros request/response onde cada registro deve ser bem-sucedido de ponta a ponta.

O sizer adaptativo encontra o maior tamanho de registro que o carrier aceita e permanece nele, recuperando-se automaticamente se as condições mudarem.

---

## Fase de Calibração (`phase=CALIBRATION`)

### Estratégia: Ascendente (padrão)

1. Começa em `--chunk-min` (padrão: 32 bytes)
2. Testa candidatos em ordem crescente: 32, 64, 128, 256, 512, 1024, 1200, 1280, 1320, 1350, 1360, 1380, 1400, 1450, 1600, 2048, 3205, 4096, 8192, 16384, 32768, 65536, 98304, 131072, 262144, 524288, 786432, 1048576 bytes
3. Para cada candidato, envia uma sonda e aguarda o eco do servidor
4. Busca binária entre o último sucesso e a primeira falha para encontrar o limite exato (resolução fina: 32 bytes)
5. Confirma o limite com maioria 2-de-3 em conexões novas (timeouts são inconclusivos e nunca votam)

Upload e download são calibrados **sequencialmente** no mesmo wire (não em paralelo).

### Estratégia: Max-First (legado, `--chunk-max-first`)

1. Começa em `--chunk-max` (padrão: 1 MiB)
2. Na primeira falha, reduz em `--chunk-shrink-step` bytes (padrão: 200)
3. Continua até estabilizar
4. Usado apenas via flag da CLI; o Android sempre usa ascendente

---

## Sizer Adaptativo em Tempo de Execução

Após a calibração, o `adaptiveSizer` ajusta os tamanhos de chunk por sessão com base em sucessos e falhas observados:

### Crescimento

- A cada `--chunk-grow-after` sucessos consecutivos (padrão: 16), o sizer tenta um tamanho maior
- Fórmula de crescimento:
  - Se existe um limite superior conhecido de falha dentro de 64 bytes do atual: busca binária em direção a ele
  - Caso contrário: aumenta em `max(atual/4, 32)` bytes
  - Nunca excede `--chunk-max`
- Após um limite de falha anterior, o limiar de crescimento é multiplicado por 8 (recuperação conservadora)

### Redução

- Após `--chunk-shrink-after` falhas consecutivas (padrão: 1), o sizer reduz
- Fórmula de redução:
  - Se `--chunk-shrink-step > 0`: `novo = atual - shrink_step` (linear)
  - Caso contrário: `novo = tamanho_bom_conhecido` ou `atual / 2` (binário)
  - Nunca abaixo de `--chunk-min`

### Tratamento de Timeout

Um timeout de rede é tratado como **limite rígido de túnel**, não como sinal de tamanho de chunk. O sizer **não é atualizado** em timeouts porque:
- A conexão física pode estar morta
- Repetir a mesma requisição após timeout pode duplicar um upload que já foi recebido

---

## Escalonamento de Workers

Após a calibração, o número de workers paralelos de upload/download é calculado:

```
alvo = 1024 * 1024 bytes  (1 MiB agregado)
workers = ceil(alvo / chunk_seguro)
workers = clamp(workers, 1, 64)
```

Por exemplo, se `chunk_seguro = 16384` bytes (16 KiB):
```
workers = ceil(1048576 / 16384) = 64
```

Isso garante que o throughput agregado alvo seja atingido mesmo em carriers altamente restritivos.

---

## Teste iPerf Sustentado

Quando `--iperf-duration > 0`, um teste de throughput sustentado é executado após a calibração:

1. Inicia `workers` goroutines paralelas
2. Cada goroutine envia sondas continuamente com tamanho `chunk_seguro` por `iperf-duration` segundos
3. Um ticker de progresso registra a velocidade agregada a cada segundo
4. Resumo final reporta total de bytes, tempo decorrido e Mbps

Útil para medir o throughput real do carrier antes de iniciar tráfego de produção.

---

## Referência de Logs

```
[D-TCP] phase=PORT_SCAN state=starting ...
[D-TCP] phase=PORT_SCAN state=tcp_reachable candidate=53 host=x.x.x.x ...
[D-TCP] phase=PORT_SCAN state=success port=53 wire=b header_mask=00 ...
[D-TCP] phase=AUTH state=success wire=b header_mask=00 clear_payload=false ...
[D-TCP] phase=CALIBRATION state=starting strategy=ascending min=32 max=1048576 ...
[D-TCP] phase=CALIBRATION fake_iperf=upload stage=sustained duration=15.0s workers=4 ...
[D-TCP] phase=CALIBRATION state=success upload=262144 download=262144 pollers=4 ...
[D-TCP] phase=WORKERS chunk=262144 safe_kb=256 workers=4 target_aggregate_kb=1024 ...
[D-TCP] phase=ACTIVE wire=b header_mask=00 clear_payload=false upload_chunk=262144 ...
adaptive upload chunk: 262144 -> 131072 after transport failure
adaptive upload chunk: 131072 -> 262144 after stable success
```
