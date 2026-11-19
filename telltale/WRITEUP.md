# Writeup : telltale

Catégorie : misc

Date de résolution : 2026-11-07

Technique principale : OOK/photodiode waveform decoding

Outils observés : python,numpy

Cible : CSCTF 2026 #9081

## Présentation

Ce document est construit à partir de la mémoire CTF partagée et des artefacts conservés dans /root/ctf/telltale. Les étapes ci-dessous reprennent uniquement les faits observés. Les captures sont réalisées sur les fichiers locaux, sans rejouer une action distante ou destructive.

## Analyse et raisonnement

### Pourquoi ça marche

Derive bit period and polarity from the waveform before decoding framing.

### Notes locales conservées

## Journal
1. 2026-11-07T13:04:03Z unknown : WAV 48kHz mono = photodiode sur LED. OOK bimodal (seuil 13000). Bit period 48 samples=1000 baud. Preamble 1010.. + SFD 11 (Ethernet-like). Signal INVERSE (idle low). ASCII MSB-first depuis offset -> flag.

## Commandes utiles

Les commandes suivantes consultent les preuves locales et sont sans effet de bord :

```bash
cd /root/ctf/telltale
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

Le flag est conservé dans le fichier local flags.txt ou flag.txt. Aucune validation externe supplémentaire n’est affirmée ici.

Flag obtenu : `CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}`

## Conclusion

La résolution repose sur la faiblesse indiquée dans la technique principale, puis sur la vérification locale du résultat conservé. Le flag final ci-dessus est copié depuis la preuve locale réellement présente.
