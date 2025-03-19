[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_virustotal-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-virustotal)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-virustotal)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-virustotal)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-virustotal)](./LICENSE)

# Virustotal Service

This Assemblyline service checks (and optionally submits) files/URLs to VirusTotal for analysis.

## Service Details

**NOTE**: This service **requires** you to have your own API key (Paid or Free).

### Execution

This service will actually submit the file to VirusTotal for analysis over the v3 REST API.

Because the file leaves the Assemblyline infrastructure, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave our system.

### Configuration

---

#### Service Configuration

|         Name         | Description                                                                                                                                                           |
| :------------------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|       api_key        | Global VirusTotal API key for the system to use if the submitter doesn't provide their own                                                                            |
|         host         | VirusTotal host defaults to external `https://www.virustotal.com` but can be specified for testing or internal hosting.                                               |
|        proxy         | Proxy to connect to VirusTotal with                                                                                                                                   |
| allow_dynamic_submit | Allow users to submit file to VirusTotal?                                                                                                                             |
|      av_config       | Configuration block that tells the service to ignore/remap certain AV verdicts from the File Report. See [Service Manifest](./service_manifest.yml) for more details. |
|        cache         | A list of databases containing a cache of VirusTotal data                                                                                                             |

##### VirusTotal cache

To configure the service to use a `cache` of VirusTotal data, see the supported backends mentioned [here](./virustotal/cache/).

#### Submission Parameters

|       Name        | Description                                                                                                  |
| :---------------: | :----------------------------------------------------------------------------------------------------------- |
|      api_key      | Individual VirusTotal API key                                                                                |
|  dynamic_submit   | Instructs the service to submit to VirusTotal if there is no existing report about the submission            |
| exhaustive_search | Performs a lookup of all network IOCs tagged that are associated to the file (recommended to use with cache) |

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Virustotal \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-virustotal

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Virustotal

Ce service d'Assemblyline vérifie (et peut soumettre) des fichiers/URL à VirusTotal pour analyse.

## Détails du service

**NOTE** : Ce service **exige** que vous ayez votre propre clé API

### Exécution

Ce service permet de soumettre un fichier à VirusTotal pour analyse via l'API REST v3.

Étant donné que le fichier quitte l'infrastructure d'Assemblyline, le système va prévenir l'utilisateur et l'informer que le fichier et les métadonnées liées à la soumission quitte notre environment.

### Configuration

---

#### Configuration du service

|         Nom          | Description                                                                                                                                                                       |
| :------------------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|       api_key        | Clé d'API VirusTotal globale pour le système à utiliser si l'auteur ne fournit pas sa propre clé d'API.                                                                           |
|         host         | L'hôte de VirusTotal est par défaut l'hôte externe `https://www.virustotal.com` mais peut être spécifié pour le test ou l'hébergement interne.                                    |
|        Proxy         | Proxy à utiliser pour se connecter à VirusTotal.                                                                                                                                  |
| allow_dynamic_submit | Autoriser les utilisateurs à soumettre un fichier à VirusTotal ?                                                                                                                  |
|      av_config       | Bloc de configuration qui indique au service d'ignorer/remapper certains verdicts AV du rapport de fichier. Voir [Service Manifest](./service_manifest.yml) pour plus de détails. |
|        cache         | Une liste de bases de données contenant un cache de données VirusTotal.                                                                                                           |

#### Paramètres de soumission

|        Nom        | Description                                                                                                                 |
| :---------------: | :-------------------------------------------------------------------------------------------------------------------------- |
|      api_key      | Clé de l'API VirusTotal                                                                                                     |
|  dynamic_submit   | Indique au service de soumettre à VirusTotal s'il n'y a pas de rapport existant sur la soumission.                          |
| exhaustive_search | Effectue une recherche de tous les IOCs réseau marqués qui sont associés au fichier (utilisation recommandée avec le cache) |

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Virustotal \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-virustotal

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
