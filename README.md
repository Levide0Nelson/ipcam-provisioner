# ipcam-provisioner

Outil d'automatisation de la découverte, l'identification et l'attribution d'adresses IP
pour installations CCTV à grande échelle, avec gestion automatique des conflits IP au
niveau 2 (MAC). Supporte Hikvision, Dahua, Tiandy et les appareils ONVIF génériques.

## Statut du projet

- **Phase 0 — Spécification** : `docs/spec_phase0.md`
- **Phase 1 — Environnement de simulation (en cours)** : pipeline complet de bout en bout
  (découverte → fingerprinting → activation → détection de conflits → résolution IP
  temporaires via canal MAC-adressé → planification → attribution) traité sur des
  caméras *simulées* (mocks UDP/HTTP imitant SADP, Dahua, Tiandy, ONVIF), sans matériel
  réel. Interface CLI + rapport de synthèse + logs JSON-lines.
- **Phase 2 — Découverte réelle (amorcée)** : transports réels validés sur la machine,
  sans matériel, via le mode `--rehearse <méthode>` (caméras virtuelles inscrites sur les
  vrais groupes/ports de diffusion). Multidiffusion WS-Discovery (`239.255.255.250:3702`)
  et diffusion broadcast SADP/Dahua/Tiandy (`37020`/`37810`/`9999`) opérationnelles ;
  scan ARP réel (table système `arp`/`/proc/net/arp`) filtré par OUI. Sélecteur de méthode
  `--method` disponible. Reste à valider : protocoles vendor sur matériel réel (les mocks
  texte Phase 1 sont à confirmer contre des réponses binaires réelles).
- **Phase 5 — Orchestration & interface (amorcée)** : assistant de configuration
  `--wizard` (menu de sélection du type de caméras, plage, passerelle, mot de passe
  par défaut), générateur de fichier de départ `--init` et **menu principal** `--menu`.
  Le rapport final affiche un **tableau du parc** (MAC, IP, vendor, modèle, activation,
  cible, état + notes conflit/IP temporaire) et la **répartition par fabricant**. Les
  caméras inactives d'usine sont **re-fingerprintées après activation** pour remplir
  modèle/série/firmware dans le rapport. Le détail des **conflits résolus** est affiché
  et le rapport peut être **exporté en JSON** (`--json rapport.json`). Depuis le **menu
  principal**, l'option 5 (répétition d'une méthode) propose un **sous-menu numéroté** :
  choisir un numéro (1-4) plutôt que de taper le nom de la méthode à la main.

## Gestion des fichiers de configuration

Création, modification et suppression sont prévues :

- `--wizard <fichier>` — créer une configuration par dialogue guidé.
- `--init <fichier>` — générer un fichier de départ (valeurs par défaut ou reprise d'une conf).
- `--config-edit <fichier>` — modifier une configuration existante : les valeurs
  actuelles sont **pré-remplies**, taper **Entrée** conserve chacune d'elles (y compris
  un mot de passe déjà défini).
- `--config-delete <fichier>` — supprimer une configuration, **avec confirmation** avant
  suppression (répondre autre chose que `o`/`oui`/`y`/`yes` l'annule).

## Assistant de configuration (`--wizard`)

Taper **Entrée** (saisie vide) conserve la valeur par défaut affichée — l'utilisateur
n'a pas à la retaper. Les valeurs incorrectes sont **refusées séance tenante** et la
question est re-posée jusqu'à obtention d'une saisie valide : adresse IPv4 à 4 octets
explicites (un `195.154.3` incomplet ou un `0.0.0.0` non routeable est rejeté), masque
de sous-réseau contigu, et plage cohérente (début ≤ fin). Le **mot de passe par défaut**
est saisi en **clair masqué** (`getpass`, aucun écho à l'écran) puis **confirmé** : il
doit être tapé deux fois à l'identique, sinon la saisie est relancée.

## Installation

```bash
python -m venv .venv
# Windows : .\.venv\Scripts\activate   |   Linux/macOS : source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
ipcam-provisioner --config config/example_site.yaml
```

Menu interactif principal (sélection d'une action : simuler, lancer le pipeline,
configurer, répétitions, quitter) :

```bash
ipcam-provisioner --menu
```

Pour exécuter le pipeline **sans matériel** (Phase 1), utiliser le site de démonstration
simulé (caméras virtuelles UDP/HTTP + réseau ARP local) :

```bash
ipcam-provisioner --simulate
```

Le rapport de synthèse est affiché sur la sortie standard ; les logs structurés
(JSON-lines) partent sur stderr (`--log-level` pour en contrôler le niveau).

### Créer une configuration (Phase 5)

Deux façons de produire un fichier YAML de site :

```bash
# 1) fichier de départ réutilisant les valeurs par défaut (ou un --config existant)
ipcam-provisioner --init config/site.yaml

# 2) assistant interactif : type de caméras, plage, passerelle, mot de passe…
ipcam-provisioner --wizard --config config/site.yaml
```

L'assistant pose les questions (Entrée = valeur par défaut) et écrit une configuration
validée. Pensez à remplacer le mot de passe par défaut `REPLACE_ME` par les identifiants
réels avant toute détection/attribution.

### Valider les transports de découverte sans matériel (Phase 2)

Une caméra virtuelle est inscrite sur le vrai groupe/port de diffusion du protocole, puis
la découverte est exécutée par le **chemin réel** (multicast/broadcast) — pas par le
simulateur :

```bash
ipcam-provisioner --rehearse onvif_ws_discovery   # multicast 239.255.255.250:3702
ipcam-provisioner --rehearse sadp                 # broadcast 255.255.255.255:37020
ipcam-provisioner --rehearse dahua_discovery      # broadcast 255.255.255.255:37810
ipcam-provisioner --rehearse tiandy_discovery     # broadcast 255.255.255.255:9999
```

Attendu : `Répétition <méthode> OK : 1 caméra(s) détectée(s).`

## Tester la découverte sur des caméras réelles (Phase 2)

### Prérequis réseau

- Le PC qui lance l'outil et les caméras doivent être **sur le même VLAN / même switch**,
  branchés directement (pas de routeur entre eux).
- Le **multicast (WS-Discovery)** traverse les ports des switchs à IGMP snooping : en cas
  de doute, tester d'abord sur un switch sans IGMP, ou vérifier que le port du PC est
  membre du groupe `239.255.255.250`.
- **Firewall** : ouvrir les ports UDP entrants/sortants utilisés par la découverte :
  `3702` (WS-Discovery), `37020` (SADP Hikvision), `37810` (Dahua), `9999` (Tiandy).
- Paramétrer l'ordinateur avec une IP fixe sur le même sous-réseau que les caméras.

### 1) Réveiller une caméra en config usine

Beaucoup de caméras sortent d'usine sur `192.168.1.64` (Hikvision/Dahua) avec le DHCP
désactivé. Brancher la caméra seule (ou sur un réseau isolé), lui donner une IP fixe sur
le même segment, puis vérifier qu'elle répond à un ping.

### 2) Scanner avec une seule méthode (recommander de commencer par WS-Discovery)

```bash
ipcam-provisioner --config config/example_site.yaml --method onvif_ws_discovery
```

Attendu : la liste des caméras ONVIF avec leur IP. Le `--method` restreint la découverte ;
répéter le flag pour plusieurs méthodes (`--method sadp --method onvif_ws_discovery`).

Puis, selon le vendor de la caméra testée :

```bash
ipcam-provisioner --config config/example_site.yaml --method sadp                # Hikvision
ipcam-provisioner --config config/example_site.yaml --method dahua_discovery     # Dahua
ipcam-provisioner --config config/example_site.yaml --method tiandy_discovery    # Tiandy
```

**Contrôles à faire sur une caméra utilisant la méthode testée :**
- la caméra apparaît bien avec sa bonne IP (celle vue dans le firmware/SADP officiel) ;
- le MAC est rempli : il vient du fallback ARP (table système). S'il est vide, lancer
  d'abord un ping vers la caméra (`ping <ip>`) pour remplir la table ARP de l'OS, relancer.
- si rien n'apparaît : vérifier firewall, VLAN, switch IGMP, et le timeout
  `discovery.timeout_seconds` dans la config YAML (augmenter à 3-5 s).

### 3) Vérifier la remplissage MAC via la table ARP

Le fallback ARP réel lit la table du système et ne garde que les adresses dont l'OUI
correspond à un vendor caméra connu. Témoin :

```bash
arp -a            # Windows   — chercher l'IP de la caméra et son adresse MAC
cat /proc/net/arp # Linux
```

Si le MAC de la caméra apparaît, la dédup fusionnera la découverte WS-Discovery (sans
MAC) avec une entrée de type `arp_oui_fallback` (avec MAC). Le pipeline a alors toutes
les informations (MAC + IP) pour la suite (conflits, attribution).

### 4) Protocole de test progressif (validé en Phase 3-6)

1. **Une seule caméra** : scanner, vérifier MAC + vendor + modèle détectés.
2. **Deux caméras en conflit volontaire** : configurer deux caméras avec la **même IP**
   usine, scanner, vérifier que le rapport signale 1 conflit et que chaque caméra est
   identifiée distinctement (MAC différents).
3. **Le parc complet** : lancer le pipeline complet (`--config site.yaml` sans
   `--simulate`). **Attention** : les étapes activation/résolution/attribution (Phase 3-4)
   modifient réellement les caméras — les valider d'abord sur du matériel de test
   isolé avant tout réseau de production.

## Tests

```bash
pytest
ruff check src tests
```

## Architecture

```
src/ipcam_provisioner/
├── models.py            Modèle de données (Camera, Conflict, AssignmentResult)
├── config.py            Chargement/validation YAML + utils IP
├── wizard.py            Assistant de configuration interactive --wizard / --init
├── net/                 Transports réels (UDP local, client HTTP)
├── discovery/           Un adaptateur par protocole + manager/dédup
├── fingerprinting/      Identification vendor/modèle/firmware (HTTP/ONVIF)
├── conflicts/           Détection + résolution L2 des conflits d'IP
├── activation/          Activation des caméras inactives (mot de passe usine)
├── assignment/          Attribution ordonnée des IP dans la plage du site
├── planning.py          Répartition des adresses cibles entre caméras
├── orchestrator.py      Pipeline complet (seul module à tout orchestrer)
├── cli.py               Rendu du rapport + commandes CLI (aucune logique métier)
├── logging_conf.py      Logs structurés JSON-lines + sortie console
└── simulation/          Caméras virtuelles + réseau simulé (Phase 1)
```

## Roadmap

1. ~~Phase 0 — Spécification~~
2. ~~Phase 1 — Environnement de simulation~~ — pipeline de bout en bout, tests 110 verts
3. Phase 2 — Module de découverte réel — **transports multicast/broadcast + ARP validés (répétition locale)** ; à confirmer sur matériel : formats SADP/vendor réels
4. Phase 3 — Fingerprinting & détection de conflits sur matériel réel
5. Phase 4 — Activation, résolution de conflits (Layer 2), attribution IP
6. Phase 5 — Orchestration & interface CLI — **--menu / --wizard / --init / --json opérationnels, rapport du parc tabulaire + répartition fabricant + détails conflits résolus + export JSON** ; GUI optionnelle envisageable
7. Phase 6 — Tests sur matériel réel & documentation finale