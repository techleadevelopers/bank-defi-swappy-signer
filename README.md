<div align="center">
<img src="https://res.cloudinary.com/limpeja/image/upload/v1770993671/swap_1_mvctri.png" alt="swap Logo" width="380">
 <h1>Motor de assinatura e sweeping para o fluxo TRON/USDT da Swappy. Gera transações TRC20 a partir de endereços filhos (XPUB/XPRV) com HMAC, anti-replay e idempotência persistida.</h1>
</div>



## Principais recursos
- **HD signing**: deriva `m/44'/195'/0'/0/{index}` a partir de `TRON_XPRV` e assina transfers TRC20.
- **HMAC + anti-replay**: headers `x-ts`, `x-nonce`, `x-signer-hmac` (HMAC-SHA256 sobre `ts.nonce.body`).
- **Allowlist**: destinos (`ALLOW_DEST`) e contratos (`ALLOW_TOKEN_CONTRACTS`) opcionais.
- **Idempotência**: tabela `signer_idempotency` em Postgres; resposta repete o mesmo `txId` para a mesma `idempotencyKey`.
- **Dual mode**:  
  - `/sign/hd/transfer` → child address (XPRV)  
  - `/sign/transfer` → single hot key (`SIGNER_PRIVATE_KEY`) para top-ups TRX/hot→cold.

## Variáveis de ambiente
Obrigatórias:
- `SIGNER_PRIVATE_KEY` — chave hot (single-key).
- `TRON_XPRV` — XPRV par do XPUB usado no backend.
- `SIGNER_HMAC_SECRET` — hex 32 bytes (igual ao backend).

Rede:
- `TRON_FULLNODE_URL` (default `https://api.trongrid.io`)
- `TRON_SOLIDITY_URL` (default `https://api.trongrid.io`)

Segurança/controles:
- `ALLOW_DEST` — CSV de endereços permitidos (ex: treasury hot/cold).
- `ALLOW_TOKEN_CONTRACTS` — CSV de contratos permitidos (USDT TRC20).
- `HMAC_MAX_SKEW_SEC` — janela de tempo para ts/nonce (default 60s).

Persistência:
- `DATABASE_URL` — Postgres para idempotência (`signer_idempotency`).

Porta:
- `PORT` (default 4001)

## Endpoints
### POST /sign/hd/transfer
Body:
```json
{
  "derivationIndex": 0,
  "to": "TRON_ADDRESS",
  "amount": "12.345678",
  "tokenContract": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
  "idempotencyKey": "unique-string"
}
```
Headers:  
`x-ts`, `x-nonce`, `x-signer-hmac`, `Content-Type: application/json`

Resposta: `{ "txId": "...", "from": "childAddress", "idempotent": true? }`

### POST /sign/transfer
Single-key (hot):
```json
{
  "to": "TRON_ADDRESS",
  "amount": "1.23",
  "tokenContract": "...",
  "idempotencyKey": "unique-string"
}
```
Mesmos headers HMAC.

## Como rodar local
```bash
cd signer
npm install
SIGNER_PRIVATE_KEY=... \
TRON_XPRV=... \
SIGNER_HMAC_SECRET=... \
ALLOW_DEST=TR... \
ALLOW_TOKEN_CONTRACTS=TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf \
DATABASE_URL=postgres://user:pass@host:5432/db \
node server.js
```

## Fluxo com o backend
1) Backend deriva endereços por ordem via XPUB; detecta depósito.  
2) SweepWorker chama `/sign/hd/transfer` com `derivationIndex` da ordem para varrer USDT → treasury.  
3) Opcional: `/sign/transfer` pode enviar TRX do hot para o child se faltar fee (top-up).

## Segurança recomendada
- Manter `TRON_XPRV` em KMS/MPC quando possível; evitar plain env em produção.  
- Expor o signer apenas em rede interna/VPC; usar rate limit + allowlist de IP.  
- Persistir nonces/anti-replay em Redis/DB se escalar para múltiplas instâncias.  
- Monitorar saldo TRX dos filhos e da hot para evitar sweeps travados por falta de fee.
