# modulo_SBOM

Validazione SBOM (Software Bill of Materials).
Sviluppato per schema CycloneDX v1.6 in formato JSON.

## Prerequisiti

- Python 3.12.10
- cyclonedx-python-lib 11.0.0


## Installazione

Utilizzare il package manager [pip](https://pip.pypa.io/en/stable/) per installare la libreria CycloneDX Python.

```bash
pip install cyclonedx-python-lib[validation]==11.0.0
```

Creare una cartella (es. modulo_SBOM)
```bash
mkdir modulo_SBOM
```
Copiare al suo interno il file modulo_SBOM.py 

## Uso

```bash
cd modulo_SBOM
python3 modulo_SBOM.py 'fileSBOM.sbom'
```
Parametri opzionali:
```bash
--max-size 'MB': dimensione massima del file SBOM di input

--output-dir 'percorso' Percorso dove viene salvato il report generato dallo strumento

-q : opzione di logging che limita la quantità di messaggi prodotti dallo strumento nel corso dell'esecuzione

--verbose : opzione di logging che incrementa la quantità di messaggi prodotti dallo strumento nel corso dell'esecuzione
```
## Esempi di utilizzo
```bash
python3 modulo_SBOM.py fileSBOM.json

python3 modulo_SBOM.py fileSBOM.json --max-size 50 --output-dir ./reports --verbose

python3 modulo_SBOM.py fileSBOM.json -q
```

## Licenza
Questo software è rilasciato da ACN - Agenzia per la Cybersicurezza Nazionale
sotto la LICENZA PUBBLICA DELL'UNIONE EUROPEA (EUPL), versione 1.2

[EUPL 1.2](https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12)

All'interno del software è utilizzata la libreria CycloneDX Python,

Copyright (c) OWASP Foundation. All Rights Reserved.
Under the terms of the Apache 2.0 license.

[Apache 2.0](http://www.apache.org/licenses/)
