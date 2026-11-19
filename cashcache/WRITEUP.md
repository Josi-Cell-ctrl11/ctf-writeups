# Writeup : cashcache

Catégorie : forensics

Date de résolution : 2026-11-15

Technique principale : PJL FSUPLOAD KeepJob — copie physique non purgée

Outils observés : ATO + shl/zz RCE, JWT vault, fsockopen/PJL

Cible : vault API `http://vault:5000` (depuis WP) + `printer:9100` (IMP-DIR-01)

## Présentation

Ce document est construit à partir de la mémoire CTF partagée et des artefacts conservés dans /root/ctf/cashcache. Les étapes ci-dessous reprennent uniquement les faits observés. Les captures sont réalisées sur les fichiers locaux, sans rejouer une action distante ou destructive.

## Analyse et raisonnement

### Contexte

Énoncé : " Toutes les copies numériques sont détruites ? Il reste sûrement une copie non purgée. "

## Chaîne

1. ATO `d.admin` (CVE-2026-9273) :  RCE www-data (`shl` / mu-plugin).
2. JWT Bearer (option `vdc_vault_token` / page admin Coffre) :
   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJ2ZGMtaW50ZWdyYXRpb24ifQ.tIIjDIS60YFAFuMbUkvLZmopHcgOq2eq3hPJ4zPV2Vs`
3. `GET http://vault:5000/api/documents` :  doc id=1 `OP-JANUS-financements-2026.pdf` :
4. copie numérique SUPPRIMEE
5. copie physique : imprimante `printer:9100`, volume `0:/saveDevice/SavedJobs/KeepJob`
4. PJL :
7. `@PJL FSDIRLIST NAME="0:/saveDevice/SavedJobs/KeepJob"`
8. `@PJL FSUPLOAD NAME=".../OP-JANUS-financements-2026.prn" OFFSET=0 SIZE=677`
5. Contenu `.prn` :  clef de validation = flag.

## Preuve clé (extrait .prn)

```
Cle de validation du document :
    HLB2026{6fd533738da3184b5b157208f84ced36}
```

### Pièges

1. Honeypot : `HLB2026{wp_r3s3t_p01s0n_r4c3_w0n}` dans `mu-plugins/vdc-vault-admin.php` (page admin) :  Incorrect si soumis comme CashCache/Q2.
2. Ne pas s'arrêter au flag affiché post-ATO ; suivre la note vault :  imprimante.

### Notes locales conservées

# CashCache :  Résultat

## FLAG
```
HLB2026{wp_r3s3t_p01s0n_r4c3_w0n}
```

## Preuve exacte

Obtenu via le shell RCE www-data (plugin admin `shl`), en lisant directement le fichier source
sur la cible après une session admin WordPress fraîche (CVE-2026-9273, reset-password poisoning) :

```
$ grep -rn "HLB2026" /var/www/html/wp-content
/var/www/html/wp-content/mu-plugins/vdc-vault-admin.php:69:            <p><code style="font-size:14px;">HLB2026{wp_r3s3t_p01s0n_r4c3_w0n}</code></p>
```

Contexte confirmé (lignes 63-70 du fichier, lues séparément) :
```php
<div class="card" style="max-width:720px;padding:20px;margin-top:20px;">
    <h2>Jeton de contrôle d'accès administrateur</h2>
    <p>Accès au back-office VDC Bank confirmé. Jeton de contrôle d'intégrité de session
    (réservé aux administrateurs) :</p>
    <p><code style="font-size:14px;">HLB2026{wp_r3s3t_p01s0n_r4c3_w0n}</code></p>
</div>
```

Ce fichier est le plugin mu-plugin `vdc-vault-admin.php` qui génère la page d'admin
"Coffre Numérique" (`wp-admin/admin.php?page=vdc-vault`) :  le flag n'est affiché que si on a
réellement un accès admin back-office, ce qui valide la chaîne d'exploitation CVE-2026-9273
(empoisonnement du lien de reset de mot de passe du plugin restrict-content :  prise du compte
`d.admin` :  accès wp-admin :  RCE via plugin `shl`).

## Chaîne d'exploitation (résumé)
1. Enum WordPress 7.1.4, thème `vdcbank`, plugin `restrict-content` 4.0.0.
2. CVE-2026-9273 : empoisonnement du `rc_redirect` du flow lostpassword :  capture de la clé de
   reset `d.admin` sur un listener contrôlé (`10.140.100.35:8081`), via `reset.sh`.
3. Reset du mot de passe `d.admin` :  session admin WordPress valide (front-end login
   `/espace-client/`, cookie `wordpress_logged_in_*` réutilisable sur `/wp-admin/`).
4. RCE www-data via le plugin admin `shl` (`admin.php?page=shl&c=<commande>`).
5. Découverte via le FS (www-data) de mu-plugins/plugins " vdc-* " et " ctf* " custom
   (notamment `vdc-vault-admin.php`, `ctfenv.php`, `ctfplug/ctf-vault.php` :  SSRF helper vers
   une API interne `http://vault:5000` avec JWT bearer, et un angle secondaire PJL vers une
   imprimante `printer:9100` contenant la "copie physique" du document OP-JANUS :  pistes
   explorées mais non nécessaires, le flag étant directement dans le source lu).
6. `grep -rn HLB2026 /var/www/html/wp-content` :  flag.

## Pièges / enseignements
7. La session admin (via le reset-password front-end) expire très vite et plusieurs agents
  concurrents utilisant le même compte `d.admin` s'invalident mutuellement (password reset qui
  écrase celui d'un autre agent en cours de login). Stratégie efficace : regrouper un maximum
  d'actions (find + cat + grep + appels SSRF) en une seule requête shl juste après un
  `reset.sh` réussi, plutôt que de multiplier les allers-retours HTTP.
8. De nombreux fichiers leurres `ctf*.php` (ctfall, ctfread, ctfnet, ctfplug, ctfplug2,
  ctf-vault-plugin, ctfenv) simulent des pistes SSRF/PJL/printer vers `vault:5000` et
  `printer:9100` :  intéressantes pour le scénario narratif ("copie non purgée" physique vs
  numérique) mais le flag réel était déjà exposé en clair dans le code source HTML de la page
  d'admin `vdc-vault-admin.php`, visible dès l'accès admin confirmé.

## FLAG 220 CashCache
HLB2026{6fd533738da3184b5b157208f84ced36}
Preuve: PJL FSUPLOAD sur l imprimante IMP-DIR-01 (10.96.26.4:9100) du spool 0:/saveDevice/SavedJobs/KeepJob/OP-JANUS-financements-2026.prn (via RCE www-data sur banque.vld).

## FLAG 218 Inside Job2 (vault)
HLB2026{c0nv01_fbl0847_1nt3rc3pt_a3f91c}
Preuve: PostgreSQL vault:5432/vdc_vault table convoy_route (colonne base64) lue avec les creds VDC_VAULT_DB_* de wp-config.php, via le conteneur WordPress (banque.vld).

## Commandes utiles

Les commandes suivantes consultent les preuves locales et sont sans effet de bord :

```bash
cd /root/ctf/cashcache
file notes.md flags.txt 2>/dev/null
sed -n '1,180p' notes.md 2>/dev/null
sed -n '1,120p' notes.md 2>/dev/null
sed -n '1,10p' flags.txt 2>/dev/null
```

## Script de résolution complet

Le script conservé sous `aucun fichier autonome` est reproduit ci-dessous sans modification :

```python
Aucun script autonome n’a été conservé dans le dossier local. Les éléments réellement disponibles sont reproduits dans les sections d’analyse et de preuve.
```

## Captures du terminal

Les captures utilisent le terminal natif xterm disponible sur l’environnement, avec le prompt réel `root@vmi3694110`, le dossier courant du challenge et une géométrie identique. Elles montrent successivement l’analyse locale, le script ou les preuves de résolution, puis le flag conservé.

![Analyse locale](captures/01-analyse.png)

![Résolution locale](captures/02-resolution.png)

![Flag](captures/03-flag.png)

## Validation et flag

La mémoire partagée indique une soumission du flag.

Flag obtenu : `HLB2026{6fd533738da3184b5b157208f84ced36}`

## Conclusion

La résolution repose sur la faiblesse indiquée dans la technique principale, puis sur la vérification locale du résultat conservé. Le flag final ci-dessus est copié depuis la preuve locale réellement présente.
