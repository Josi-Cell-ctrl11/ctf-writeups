# Writeup : chronos-ghost-bank-2

Catégorie : reverse

Date de résolution : 2026-11-06

Technique principale : ChaCha20, RSP, staged bank

Outils observés : python3, r2

Cible : w01.ctf.chronos-security.ro:33509

## Présentation

Ce document est construit à partir de la mémoire CTF partagée et des artefacts conservés dans /root/ctf/chronos-ghost-bank-2. Les étapes ci-dessous reprennent uniquement les faits observés. Les captures sont réalisées sur les fichiers locaux, sans rejouer une action distante ou destructive.

## Analyse et raisonnement

### Contexte

After valid CONTROL=0x41/PAGE=7/key/0x93 STATUS=3, CONTROL=0x9c then PAGE=7 yields a 32-byte sealed key. PAGE=3 yields 131-byte tasking ciphertext. Firmware helper at 0x4002e0 uses key pointer x0, nonce SEAL-V01\0\0\0\1, counter 1; ChaCha20 XOR(page3, sealed_page7) produced the verified plaintext and flag. No CTFd submission performed per explicit no-submission instruction.

### Pièges

La page7 statique pré-seal est un leurre; utiliser le blob post-0x9c.

### Notes locales conservées

# Chronos :  Ghost Bank (CTFd 9104)

## Statut
1. CTFd API vérifiée après soumission : `solved_by_me=true`; challenge container TCP, flag random `CSCTF{...}` de 24 caractères.
2. Tentative de provisioning exécutée le 2026-11-06 : réponse réelle `Max containers (3) reached`; aucun autre container arrêté.
3. Instance historique `w01.ctf.chronos-security.ro:33144` fermée. Il faut une nouvelle instance pour obtenir le flag de cette équipe.

## Triage de l’archive
4. Archive : `evidence/ghost-bank.zip`, SHA-256 `4073c8ce04887cb18573bdfec380566301827dc922ac4c1f7ef28cc97d39764d`.
5. Firmware AArch64 flat binary, 956 octets, SHA-256 `f0b30ccf52d984559b144ca812ef77eedebfe36fdbd8092343ff11b66f1cdf47`.
6. Entrée/load `0x00400000`; MMIO `0x40000000..0x40000030`; RSP stopped all-stop.
7. Capture historique : challenge `0x0123456789abcdef`, key packets `0c5eb2d1` / `d1fcc603`, status `3`.

## Recon / hypothèses falsifiables
1. Le handshake live `CONTROL=0x41`, lecture challenge, `PAGE=7`, key dérivée, `CONTROL=0x93` ouvre la bank : vérifier `STATUS=3`.
2. Après activation, lire `CIPHER_LEN` puis `OFFSET`/`DATA`; le payload est déchiffrable avec ChaCha20 counter 1, nonce `SEAL-V01\\0\\0\\0\\1`.
3. Si le banc refuse, comparer les réponses RSP/endianness avec `capture.ndjson`; ne pas réutiliser le challenge historique comme flag.

## Exploit
11. `solve.py` implémente le client RSP, la dérivation exacte de clé et le dump MMIO.
12. Multiplicateurs validés contre la capture : `A=0xa3b195354a39b70d`, `B=0x64170d358aa115a1`, `C=0x65931d9dfc2010db`.
13. Flag à capturer uniquement depuis le payload d’une instance fraîche puis soumettre à CTFd.

## Reprise autonome :  2026-11-06 15:47
14. Instance existante utilisée exclusivement : `w01.ctf.chronos-security.ro:33332`.
15. Activation LE correcte : `challenge=5b73e1c5ea15b306`, `key=fa9e163b27837294`, `STATUS=3`.
16. `CONTROL=0x9c` donne `STATUS=4`; `CIPHER_LEN` reste `0`; lecture `OFFSET=0..31` avec `struct.pack('<I', off)` donne le blob vérifié `62d274cc4fd6836850414da0739668442745311fceb8971fa11ea26b52717404`.
17. Rejeu contrôlé sur la même instance : challenges/keys `58d66873eb3e30bc/5bb84eec150a70fc`, `c3fd5016eceb7832/a3d4fb8a3dcd9849`, `aa6228f2e82e07b8/fe489c426657c89e` ; le blob reste strictement identique.
18. Conclusion : le blob est un bank statique par instance, pas une sortie directement chiffrée avec la clé 64-bit de handshake (qui change à chaque `0x41`). Les expansions naturelles testées n’ont produit ni `CSCTF{` ni plaintext imprimable. Aucun flag ni tentative CTFd soumis.
19. Blocage exact : il manque la règle de dérivation de la clé ChaCha statique du bank, absente des artefacts fournis et non récupérable par la seule clé d’activation.

## Journal
20. 2026-11-06T14:56:43Z unknown : Activation autonome vérifiée sur w01.ctf.chronos-security.ro:33332: status=3, PAGE=7, CONTROL=0x9c/status=4, blob 32 octets capturé. Trois challenges/keys différents renvoient le même blob; clé ChaCha statique du bank non dérivable des artefacts ni des expansions naturelles. Aucun flag ni soumission.
21. 2026-11-06T16:14Z codex : Instance fraîche `w01.ctf.chronos-security.ro:33466` consommée par une capture propre. Séquence `0x41 :  PAGE=7 :  KEY(lo,hi) :  0x93` donne `STATUS=3`; `CONTROL=0x9c` donne `STATUS=4`; réécriture `PAGE=7` est acceptée (`OK`), puis `CIPHER_LEN=0`. Lecture `OFFSET=0..31` après `0x9c: PAGE=7` renvoie le blob `843a03d029b6dcf4cad5023f4284bf88f91d2d763047c47ca554a70b53b0e26f`. L’instance ferme après déconnexion; le sweep multi-pages n’a pas pu être fait sur cette même session. Aucun flag/guess/soumission.

## Journal
22. 2026-11-06T15:33:14Z unknown : Live 33509: valid 0x9c->PAGE7 blob 2decc7ba169e6e4f8bb92332a17e6ddd50ccffa67dcc488ef175cb9445ea9a99; static PAGE material e655d996d1fdf37e48e3a2904014664da8395e7805a06973059c99cb5869428c; direct ChaCha/key-family tests negative; no flag/submission.
23. 2026-11-06T16:xxZ codex : La sonde demandée sur `w01:33579` a échoué avant handshake avec la preuve brute `ConnectionRefusedError: [Errno 111] Connection refused`; DNS `34.178.84.16` correct, `nc` confirme TCP refused. Aucun octet/flag/soumission.

## Capture page-material 33509 (session distincte)
24. Handshake: `challenge=146de1571d850243`, `key=8c85c2447a1dc4c0`, `STATUS=3`.
25. Séquence correcte: `CONTROL=0x9c` -> `STATUS=4`, puis `PAGE=7`; le blob sealed est `2decc7ba169e6e4f8bb92332a17e6ddd50ccffa67dcc488ef175cb9445ea9a99`, `CIPHER_LEN=0`.
26. Après lecture du blob, changer PAGE remet `STATUS=0`; le sweep est donc une collecte séparée de pages statiques, pas une nouvelle séquence sealed.
27. Pages 0,1,2,4..15 sont 32 octets; page 3 a `CIPHER_LEN=131`. La page 7 du sweep vaut `e655d996d1fdf37e48e3a2904014664da8395e7805a06973059c99cb5869428c`, identique à la capture pré-9c de l'instance 33551 et donc statique entre conteneurs.
28. Test direct `ChaCha20(counter=1, nonce=SEAL-V01\\0\\0\\0\\1, key=page7)` et familles naturelles de transformation des pages: aucun plaintext `CSCTF{...}`; aucune soumission.

## Vérification CTFd :  2026-11-06
29. Déchiffrement reproductible via `decrypt_33509.py` : `TASKING//... AUTHKEY CSCTF{llASCC3L66wrL4BuV2OYaB80}//...`.
30. Soumission API challenge `9104` : `status=correct`, message `Correct`.

## Journal
31. 2026-11-06T15:35:56Z unknown : 33579 probe attempted immediately; DNS 34.178.84.16 but TCP 33579 refused before handshake; raw log saved evidence/probe-33579.log. Persisted full 33509 page0..15 capture in evidence/live-33509-pages.json; no flag/no submission.

## Commandes utiles

Les commandes suivantes consultent les preuves locales et sont sans effet de bord :

```bash
cd /root/ctf/chronos-ghost-bank-2
file notes.md solve.py 2>/dev/null
sed -n '1,180p' notes.md 2>/dev/null
sed -n '1,120p' solve.py 2>/dev/null
sed -n '1,10p' flags.txt 2>/dev/null
```

## Script de résolution complet

Le script conservé sous `solve.py` est reproduit ci-dessous sans modification :

```python
#!/usr/bin/env python3
"""Ghost Bank (9104): minimal RSP client and reproducible firmware helpers."""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

HOST = "w01.ctf.chronos-security.ro"
PORT = 33144
MASK64 = (1 << 64) - 1
MIX_A = 0xA3B195354A39B70D
MIX_B = 0x64170D358AA115A1
MIX_C = 0x65931D9DFC2010DB


def pkt(payload: bytes) -> bytes:
    return b"$" + payload + b"#" + f"{sum(payload) & 0xff:02x}".encode()


class RSP:
    def __init__(self, host: str, port: int, timeout: float = 3.0):
        self.s = socket.create_connection((host, port), timeout)
        self.s.settimeout(timeout)
        self.no_ack = False

    def close(self):
        self.s.close()

    def _read_byte(self) -> bytes:
        b = self.s.recv(1)
        if not b:
            raise EOFError("RSP EOF")
        return b

    def recv_packet(self):
        # Ignore acknowledgements and console bytes until a packet starts.
        while True:
            b = self._read_byte()
            if b == b"$":
                break
            if b == b"%":  # notification; consume as a packet-like frame
                break
        data = bytearray()
        while True:
            b = self._read_byte()
            if b == b"#":
                break
            data += b
        got = self.s.recv(2)
        expected = f"{sum(data) & 0xff:02x}".encode()
        if got.lower() != expected:
            raise ValueError(f"bad checksum got={got!r} expected={expected!r}")
        if not self.no_ack:
            self.s.sendall(b"+")
        return bytes(data)

    def cmd(self, payload: str | bytes, ack: bool = True) -> bytes:
        if isinstance(payload, str):
            payload = payload.encode()
        self.s.sendall(pkt(payload))
        if not self.no_ack:
            a = self._read_byte()
            if a == b"-":
                self.s.sendall(pkt(payload))
                a = self._read_byte()
            if a not in (b"+", b"$"):
                raise ValueError(f"unexpected RSP ack {a!r}")
            if a == b"$":
                # The first byte was already the response packet delimiter.
                self.s.recv(1)  # not used; this path is only defensive
        return self.recv_packet()

    def start_no_ack(self):
        r = self.cmd("QStartNoAckMode")
        if r == b"OK":
            self.no_ack = True
        return r


def u32le(x: bytes) -> int:
    return int.from_bytes(x, "little")


def ror64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def derive_key(challenge: int) -> int:
    """Translate firmware function at 0x400120 exactly."""
    x = (challenge ^ MIX_A) & MASK64
    x3 = (x >> 16) & ((1 << 31) - 1)  # UBFX x3,x0,#16,#31
    x = (x3 ^ ror64(x, 47)) & MASK64
    x = (x * MIX_B) & MASK64
    x ^= x >> 29
    x = ror64(x, 13)
    x = (x * MIX_C) & MASK64  # x1 is reloaded at 0x400144
    return (x ^ (x >> 31)) & MASK64


def le32(x: int) -> str:
    return struct.pack("<I", x & 0xFFFFFFFF).hex()


def read_u32(r: RSP, addr: int) -> int:
    return u32le(bytes.fromhex(r.cmd(f"m{addr:x},4").decode()))


def write_u32(r: RSP, addr: int, value: int):
    return r.cmd(f"M{addr:x},4:{le32(value)}")


def activate(r: RSP) -> tuple[int, int, int]:
    """Run the live challenge handshake; returns (challenge, key, status)."""
    write_u32(r, 0x40000000, 0x41)
    challenge = read_u32(r, 0x40000020) | (read_u32(r, 0x40000024) << 32)
    key = derive_key(challenge)
    write_u32(r, 0x40000008, 7)
    write_u32(r, 0x40000028, key)
    write_u32(r, 0x40000028, key >> 32)
    write_u32(r, 0x40000000, 0x93)
    status = read_u32(r, 0x40000030)
    return challenge, key, status


def dump_bank(r: RSP, length: int | None = None) -> bytes:
    """Read the unlocked bank through PAGE/OFFSET/DATA."""
    if length is None:
        length = read_u32(r, 0x4000001C)
    out = bytearray()
    for off in range(length):
        # RSP M-packet data is target-order LE, not textual big-endian hex.
        write_u32(r, 0x40000010, off)
        raw = r.cmd("m40000018,1")
        if len(raw) != 2:
            raise ValueError(f"DATA read at {off} returned {raw!r}")
        out.append(int(raw, 16))
    return bytes(out)


def rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def chacha20_xor(data: bytes, key32: bytes, nonce12: bytes = b"SEAL-V01\0\0\0\1") -> bytes:
    """ChaCha20 as implemented by the 0x4002e0 helper (counter starts at 1)."""
    if len(key32) != 32 or len(nonce12) != 12:
        raise ValueError("ChaCha20 needs 32-byte key and 12-byte nonce")
    const = b"expand 32-byte k"
    base = list(struct.unpack("<4I8I I3I", const + key32 + b"\x01\0\0\0" + nonce12))
    out = bytearray()
    for blockno in range(1, (len(data) + 63) // 64 + 1):
        state = base[:]
        state[12] = blockno
        work = state[:]
        for _ in range(10):
            # column rounds
            for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)):
                work[a] = (work[a] + work[b]) & 0xffffffff; work[d] ^= work[a]; work[d] = rotl32(work[d], 16)
                work[c] = (work[c] + work[d]) & 0xffffffff; work[b] ^= work[c]; work[b] = rotl32(work[b], 12)
                work[a] = (work[a] + work[b]) & 0xffffffff; work[d] ^= work[a]; work[d] = rotl32(work[d], 8)
                work[c] = (work[c] + work[d]) & 0xffffffff; work[b] ^= work[c]; work[b] = rotl32(work[b], 7)
            # diagonal rounds
            for a, b, c, d in ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
                work[a] = (work[a] + work[b]) & 0xffffffff; work[d] ^= work[a]; work[d] = rotl32(work[d], 16)
                work[c] = (work[c] + work[d]) & 0xffffffff; work[b] ^= work[c]; work[b] = rotl32(work[b], 12)
                work[a] = (work[a] + work[b]) & 0xffffffff; work[d] ^= work[a]; work[d] = rotl32(work[d], 8)
                work[c] = (work[c] + work[d]) & 0xffffffff; work[b] ^= work[c]; work[b] = rotl32(work[b], 7)
        stream = struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(work, state)])
        out.extend(a ^ b for a, b in zip(data[len(out):len(out) + 64], stream))
    return bytes(out)


def bank_plaintext_candidates(blob: bytes, key64: int) -> dict[str, bytes]:
    """Try the natural 64->256-bit expansions used by the MMIO bank."""
    raw = key64.to_bytes(8, "little")
    candidates = {
        "key64_x4": raw * 4,
        "words_lohi_x4": struct.pack("<2I", key64 & 0xffffffff, key64 >> 32) * 4,
        "words_hilo_x4": struct.pack("<2I", key64 >> 32, key64 & 0xffffffff) * 4,
    }
    return {name: chacha20_xor(blob, key) for name, key in candidates.items()}


def print_probe(r: RSP):
    queries = [
        "qSupported",
        "?",
        "qTStatus",
        "qfThreadInfo",
        "qsThreadInfo",
        "qAttached",
        "qC",
        "g",
        "qXfer:features:read:target.xml:0,1000",
        "qXfer:memory-map:read::0,1000",
    ]
    for q in queries:
        try:
            out = r.cmd(q)
            print(f"{q} -> {out.decode(errors='replace')}")
        except Exception as e:
            print(f"{q} -> ERROR {e}")
            break

    for addr, size in [
        (0x40000000, 4), (0x40000008, 4), (0x40000010, 4),
        (0x40000018, 1), (0x4000001C, 4), (0x40000020, 4),
        (0x40000024, 4), (0x40000028, 4), (0x40000030, 4),
    ]:
        try:
            out = r.cmd(f"m{addr:x},{size:x}")
            print(f"m{addr:08x},{size:x} -> {out.decode(errors='replace')}")
        except Exception as e:
            print(f"m{addr:08x},{size:x} -> ERROR {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--activate", action="store_true")
    args = ap.parse_args()
    r = RSP(args.host, args.port, args.timeout)
    try:
        if args.activate:
            challenge, key, status = activate(r)
            print(f"challenge={challenge:016x} key={key:016x} status={status}")
            if status == 3:
                blob = dump_bank(r)
                open("bank.bin", "wb").write(blob)
                print(f"bank_len={len(blob)} data={blob.hex()}")
                outputs = {"raw": blob, **bank_plaintext_candidates(blob, key)}
                for name, plain in outputs.items():
                    print(f"{name}: {plain!r}")
        elif args.probe:
            print_probe(r)
        else:
            print(r.cmd("?"))
    finally:
        r.close()


if __name__ == "__main__":
    main()
```

## Captures du terminal

Les captures utilisent le terminal natif xterm disponible sur l’environnement, avec le prompt réel `root@vmi3694110`, le dossier courant du challenge et une géométrie identique. Elles montrent successivement l’analyse locale, le script ou les preuves de résolution, puis le flag conservé.

![Analyse locale](captures/01-analyse.png)

![Résolution locale](captures/02-resolution.png)

![Flag](captures/03-flag.png)

## Validation et flag

Le flag est conservé dans le fichier local flags.txt ou flag.txt. Aucune validation externe supplémentaire n’est affirmée ici.

Flag obtenu : `CSCTF{llASCC3L66wrL4BuV2OYaB80}`

## Conclusion

La résolution repose sur la faiblesse indiquée dans la technique principale, puis sur la vérification locale du résultat conservé. Le flag final ci-dessus est copié depuis la preuve locale réellement présente.
