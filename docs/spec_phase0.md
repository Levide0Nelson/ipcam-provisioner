# Spécification — Outil d'attribution IP pour caméras IP (Phase 0)

## 1. Vue d'ensemble & objectifs
Outil d'automatisation de la découverte, l'identification et l'attribution d'adresses IP
pour des installations CCTV, avec gestion automatique des conflits au niveau 2 (MAC),
pour des sites allant de 10-30 caméras (petits sites) à 300-1000+ caméras (grands sites),
sur un parc multi-vendor : Hikvision, Dahua, Tiandy, et appareils ONVIF génériques.

## 2. Périmètre du MVP
**In scope :**
- Découverte via protocoles propriétaires (SADP Hikvision, protocole Dahua, protocole Tiandy)
  + fallback générique (WS-Discovery/ONVIF, scan ARP + OUI)
- Fingerprinting vendor/modèle
- Détection de conflits IP entre appareils découverts
- Résolution de conflit au Layer 2 (broadcast ciblé par MAC)
- Activation des caméras inactives (mot de passe par défaut configurable — requis avant
  toute configuration sur Hikvision/Dahua neufs)
- Attribution ordonnée d'IP dans une plage définie par site
- Interface CLI avec logs structurés et rapport de synthèse final
- Fichier de config YAML par site (plage IP, credentials, timeouts, limites de concurrence)

**Out of scope (MVP) :**
- GUI (prévu comme simple remplacement de la couche présentation plus tard)
- Persistance / reprise d'exécution interrompue (à réévaluer après tests d'échelle en Phase 1)
- Configuration automatique de VLAN / ports switch
- Monitoring continu post-attribution
- Orchestration multi-site simultanée (un run = un site/subnet)

## 3. Modèle de données

### 3.1 `Camera`
Découpage par étape du pipeline qui remplit chaque attribut : une valeur par défaut
signifie "étape pas encore atteinte", pas "erreur".

**Connu dès la découverte (toujours renseigné) :**
- `mac_address: str`
- `ip_address: str` — adresse actuelle (souvent une IP usine par défaut, ex. 192.0.0.64
  pour un Hikvision neuf, ou un bail DHCP)
- `discovery_method: Enum{SADP, DAHUA_DISCOVERY, TIANDY_DISCOVERY, ONVIF_WS_DISCOVERY, ARP_OUI_FALLBACK}`
- `discovered_at: datetime`
- `raw_discovery_payload: dict` — conservé pour debug/re-parsing sans requêter à nouveau

**Partiellement connu à la découverte (fiabilité variable selon la méthode) :**
- `vendor: Optional[str]`
- `vendor_confirmed: bool` — True si `discovery_method` est propriétaire (SADP ⇒ Hikvision
  certain), False si seulement deviné par OUI, à confirmer par le fingerprinting

**Rempli progressivement par les étapes suivantes :**
- `model: Optional[str]` — fingerprinting
- `serial_number: Optional[str]` — fingerprinting
- `firmware_version: Optional[str]` — fingerprinting
- `activation_status: Enum{ACTIVE, INACTIVE, UNKNOWN} = UNKNOWN` — fingerprinting/activation
- `has_conflict: bool = False` — détection de conflits
- `target_ip: Optional[str]` — planification d'attribution
- `assignment_status: Enum{PENDING, IN_PROGRESS, SUCCESS, FAILED} = PENDING`
- `last_error: Optional[str]` — posé par n'importe quelle étape en échec, ne fait jamais
  planter le pipeline global

### 3.2 `Conflict`
- `conflicting_ip: str`
- `camera_macs: List[str]` — référence par MAC (pas par objet) pour éviter la duplication
  d'état mutable
- `detected_at: datetime`
- `resolution_status: Enum{UNRESOLVED, RESOLVING, RESOLVED, FAILED} = UNRESOLVED`
- `resolution_method: Optional[str]`

### 3.3 `AssignmentResult` (rapport final)
- `site_name: str`
- `started_at / finished_at: datetime`
- `total_discovered / total_assigned / total_failed / total_conflicts_detected / total_conflicts_resolved: int`
- `cameras: List[Camera]` — état final de chaque appareil
- `errors: List[str]` — erreurs au niveau pipeline (pas par caméra)

## 4. Architecture modulaire
```
discovery/          → un adaptateur par protocole, interface commune
fingerprinting/      → identification vendor/modèle/firmware
conflicts/           → détection + résolution L2
activation/           → activation via mot de passe par défaut
assignment/           → attribution IP ordonnée
orchestrator.py       → pipeline complet, seul module autorisé à tout appeler
cli.py                → formatage/affichage uniquement, jamais de logique métier
```

## 5. Contrats entre modules
```python
discovery.discover_all(config)            -> List[Camera]   # async, méthodes en parallèle, dédup par MAC
fingerprint.identify(camera)               -> Camera         # async, 1 appel HTTP/ONVIF/API vendor
conflicts.detect(cameras)                  -> List[Conflict]
conflicts.resolve(conflict, cameras_by_mac)-> Conflict        # L2, broadcast ciblé MAC
activation.activate(camera, default_pwd)   -> Camera
assignment.assign(camera, target_ip, creds)-> Camera
orchestrator.run(config)                   -> AssignmentResult  # seul module à tout orchestrer
cli.render(result)                         -> None              # seul module à formatter/afficher
```

**Règle de concurrence :** chaque appel réseau par appareil (fingerprint, activate, assign)
tourne sous un `asyncio.Semaphore` borné par `config.concurrency.max_parallel_requests`,
pour qu'un site de 1000 caméras n'inonde pas le switch de requêtes simultanées. La
découverte est broadcast-based et n'est pas concernée par cette limite — c'est un envoi +
une fenêtre d'écoute, indépendamment du nombre d'appareils.

## 6. Configuration utilisateur (YAML)
```yaml
site_name: "Site A"
ip_range:
  start: 192.168.1.10
  end: 192.168.1.250
subnet_mask: 255.255.255.0
gateway: 192.168.1.1
vendors:
  hikvision:
    default_password: "REPLACE_ME"
  dahua:
    default_password: "REPLACE_ME"
  tiandy:
    default_password: "REPLACE_ME"
concurrency:
  max_parallel_requests: 50
discovery:
  timeout_seconds: 5
  methods: [sadp, dahua_discovery, tiandy_discovery, onvif_ws_discovery, arp_oui_fallback]
```

## 7. Gestion des erreurs & logging
- `logging` standard Python : logs structurés JSON-lines (parsables à l'échelle) +
  sortie console lisible séparée côté CLI
- Niveaux : DEBUG=payloads bruts, INFO=progression par caméra, WARNING=conflit
  détecté/retry, ERROR=échec caméra individuelle, CRITICAL=échec pipeline
  (ex. impossible de binder l'interface réseau)
- **Isolation par caméra :** un échec sur une caméra pose `last_error` +
  `assignment_status=FAILED`, ne remonte jamais d'exception hors de la boucle
  de l'orchestrateur
- **Retry :** erreurs réseau transitoires → 2 tentatives max, backoff exponentiel
  (0.5s, 1.5s), puis FAILED

## 8. Critères d'acceptation par phase
- **Phase 1 :** caméras simulées (mocks UDP/HTTP imitant SADP/Dahua/Tiandy/ONVIF)
  traitées correctement de bout en bout par le pipeline, sans matériel réel
- **Phase 2 :** le module discovery réel retourne MAC/IP/vendor exacts pour au moins
  2 caméras réelles de vendors différents sur le réseau de test
- **Phase 3 :** conflit correctement détecté sur IP dupliquée ; fingerprinting
  identifie correctement vendor/modèle pour les 4 familles de vendors ciblées
- **Phase 4 :** résolution L2 validée sur un vrai cas d'IP dupliquée ; activation
  réussie sur une caméra réelle en config usine ; attribution réussie dans une plage définie
- **Phase 5 :** run orchestré complet via CLI sur un site simulé de 300+ caméras,
  dans un budget de temps acceptable (à chiffrer une fois la Phase 1 en place),
  avec un rapport de synthèse correct
- **Phase 6 :** run complet validé sur matériel réel (Hikvision + Tiandy minimum)
  sur le banc de test de Nel

## 9. Prérequis techniques
- IPv4 / subnetting
- ARP et relation IP/MAC
- UDP/TCP, unicast/broadcast/multicast
- XML parsing, asyncio (appris en cours de projet)
