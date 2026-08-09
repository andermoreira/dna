# ADR 001 — Armazenamento do segredo HMAC do daemon

- **Status:** aceito
- **Data:** 2026-08-09

## Contexto

A camada 2 do POC valida um payload assinado com HMAC-SHA256 por um daemon local.
Para recomputar o HMAC a cada verificação, o servidor precisa da **chave original** do
daemon — um hash da chave (como o `secret_hash` previsto no data model da spec
`specs/terminal-auth-poc.md`) não permite validar assinaturas. A spec era internamente
incoerente nesse ponto: previa armazenar só o hash e, ao mesmo tempo, exigia validação
de HMAC no verify.

A implementação original gravava a chave **em claro** na coluna
`daemon_secrets.secret_key`, o que permitia forjar a camada 2 de todos os terminais a
partir de um vazamento apenas do arquivo SQLite (backup, dump, cópia do volume).

## Decisão

Armazenar a chave **cifrada em repouso** com AES-256-GCM
(`server/src/services/secret-vault.js`), no formato `enc:v1:<iv>:<tag>:<ciphertext>`.

Material de chave da cifra, em ordem de preferência:

1. `SECRET_ENC_KEY` (env, base64 de 32 bytes) — injeção externa, recomendada.
2. Arquivo `server/data/secret-enc.key` (0600), gerado no primeiro uso — default do POC.

Linhas legadas sem o prefixo `enc:v1:` são lidas como texto claro (bancos locais
anteriores à mudança); falha de decifração retorna `null` e a validação HMAC falha
fechada.

## Consequências

- Vazamento **somente do banco** (dump SQL, backup do `.db`) não expõe mais as chaves.
- Com o default do POC, a chave da cifra vive no **mesmo volume** que o banco
  (`server/data/`); um atacante com acesso ao volume inteiro ainda decifra. Para
  separar os domínios de confiança, injetar `SECRET_ENC_KEY` via ambiente/secret
  manager — caminho de produção.
- Alternativas descartadas:
  - **Só hash da chave** (spec original): impossibilita recomputar o HMAC — inviável.
  - **Assinatura assimétrica (WebAuthn-style)**: elimina o segredo compartilhado, mas
    muda o protocolo do daemon e está fora do escopo do POC (documentado como caminho
    de produção no README).
