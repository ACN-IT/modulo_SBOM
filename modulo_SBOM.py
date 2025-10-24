# !/usr/bin/env python3
"""
===================================================
modulo_SBOM v.1.0
Validazione SBOM (Software Bill of Materials)
Sviluppato per schema CycloneDX v1.6 formato Json
===================================================
LICENZA DEL SOFTWARE
Questo software è rilasciato da ACN - Agenzia per la Cybersicurezza Nazionale
sotto la LICENZA PUBBLICA DELL'UNIONE EUROPEA (EUPL), versione 1.2
https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12

=======================================
All'interno del software è utilizzata la libreria CycloneDX Python, 
Copyright (c) OWASP Foundation. All Rights Reserved.
Under the terms of the Apache 2.0 license.
http://www.apache.org/licenses/

===================================================
PREREQUISITI:
- Python 3.12.10
- cyclonedx-python-lib 11.0.0
===================================================

Installazione libreria CycloneDX:
pip install "cyclonedx-python-lib[validation]==11.0.0"
===================================================

Esempi di utilizzo:
python modulo_SBOM.py fileSBOM.json
python modulo_SBOM.py fileSBOM.json --max-size 50 --output-dir ./reports --verbose
python modulo_SBOM.py fileSBOM.json -q
===================================================

"""

import json
import sys
import re
import os
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional, Union, IO
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
import logging

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

# =================================================================================
# CONFIGURAZIONE E COSTANTI
# =================================================================================

class ValidationLevel(Enum):
    """Enumerazione per i diversi livelli di validazione"""
    QUIET = "silenzioso"
    NORMAL = "normale"
    VERBOSE = "dettagliato"

@dataclass
class ValidationConfig:
    """Classe di configurazione per contenere tutti i parametri di validazione"""
    max_size_mb: int = 20
    output_dir: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    skip_schema: bool = False
    validation_level: ValidationLevel = ValidationLevel.NORMAL

@dataclass
class ValidationResults:
    """Classe dati per contenere i risultati di validazione e le statistiche"""
    schema_valid: bool = False
    metadata_valid: bool = False
    schema_skipped: bool = False
    components_total: int = 0
    services_total: int = 0
    valid_components: List[Tuple[str, int]] = field(default_factory=list)
    valid_services: List[Tuple[str, int]] = field(default_factory=list)
    component_stats: Optional[Dict] = None
    service_stats: Optional[Tuple] = None
    processing_time: float = 0.0

# Definizioni dei campi - ottimizzate come frozen set per ricerche più veloci
MINIMUM_COMPONENT_FIELDS = frozenset(["type", "name", "version", "manufacturer"])
ADDITIONAL_COMPONENT_FIELDS = frozenset(["cpe", "purl", "swid", "swhid", "properties", "hashes", "externalReferences"])
COMPONENT_ROLES = frozenset(["manufacturer"])

MINIMUM_SERVICE_FIELDS = frozenset(["name", "version", "provider"])
ADDITIONAL_SERVICE_FIELDS = frozenset(["description", "properties", "externalReferences"])
SERVICE_ROLES = frozenset(["provider"])

# Pattern regex
class RegexPatterns:
    """Pattern regex compilati per la validazione - compilati una volta per migliori prestazioni"""
    PURL = re.compile(r"^pkg:[a-zA-Z0-9.+-]+/.+")
    SWID = re.compile(r"^[a-zA-Z0-9_.:-]+$")
    SWHID = re.compile(r"^swh:1:.+:.{40}$")
    CPE_2_3 = re.compile(r'^cpe:2\.3:[aho]:[a-z0-9_\-\.]+:[a-z0-9_\-\.]+:[^:]*(:[^:]*){0,9}$', re.IGNORECASE)
    CPE_2_2 = re.compile(r'^cpe:/[aho]:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+(?::(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*){0,4}$', re.IGNORECASE)

# Paesi in whitelist - utilizzo di frozenset per ricerca O(1)
WHITELISTED_COUNTRIES = frozenset([
    "AL", "AT", "BE", "BG", "CA", "CY", "CZ", "DE", "DK", "EE",
    "EL", "ES", "FI", "FR", "GB", "GR", "HR", "HU", "IE", "IS",
    "IT", "LT", "LU", "LV", "ME", "MK", "MT", "NL", "NO", "PL",
    "PT", "RO", "SE", "SK", "SI", "TR", "US"])

# Costanti per la formattazione dell'output
class OutputFormat:
    """Costanti per la formattazione coerente dell'output"""
    BLOCK_SEP = "=" * 40
    ROW_SEP = "-" * 40
    SUCCESS = "✅"
    ERROR = "❌"
    WARNING = "⚠️"

# =================================================================================
# ECCEZIONI PERSONALIZZATE
# =================================================================================

class SBOMValidationError(Exception):
    """Eccezione base per errori di validazione SBOM"""
    pass

class FileValidationError(SBOMValidationError):
    """Eccezione per errori di validazione dei file"""
    pass

class SchemaValidationError(SBOMValidationError):
    """Eccezione per errori di validazione dello schema"""
    pass

# =================================================================================
# CLASSE VALIDATORE SBOM
# =================================================================================

class SBOMValidator:
    """
    Validatore SBOM

    Questa classe incapsula tutta la logica di validazione e mantiene lo stato
    """

    def __init__(self, config: ValidationConfig):
        """
        Inizializza il validatore SBOM con la configurazione

        Args:
            config: Oggetto ValidationConfig contenente tutte le impostazioni
        """
        self.config = config
        self.output_lines: List[str] = []
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """
        Configura il logging in base al livello di validazione

        Returns:
            Istanza di logger configurato
        """
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG if self.config.verbose else logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _log_info(self, message: str) -> None:
        """Registra messaggio informativo rispettando la modalità silenziosa"""
        if not self.config.quiet:
            print(message)

    def _log_verbose(self, message: str) -> None:
        """Registra messaggio dettagliato solo in modalità verbose"""
        if self.config.verbose and not self.config.quiet:
            print(f"[DETTAGLIATO] {message}")

    def _add_output_line(self, line: str) -> None:
        """
        Aggiunge una riga al buffer di output con ottimizzazione della memoria

        Args:
            line: Riga da aggiungere all'output
        """
        self.output_lines.append(line)
        # Opzionale: implementare streaming su file per output molto grandi
        # per ridurre l'uso della memoria

    @contextmanager
    def _file_reader(self, filepath: str):
        """
        Context manager per la lettura sicura dei file

        Args:
            filepath: Percorso del file da leggere

        Returns:
            Handle del file aperto
        """
        try:
            with open(filepath, "r", encoding="utf-8") as file_handle:
                yield file_handle
        except FileNotFoundError:
            raise FileValidationError(f"File non trovato: {filepath}")
        except PermissionError:
            raise FileValidationError(f"Permessi insufficienti per leggere il file: {filepath}")
        except Exception as e:
            raise FileValidationError(f"Errore inaspettato nell'aprire il file: {e}")

    def validate_input_file(self, filepath: str) -> None:
        """
        Validazione completa del file di input con segnalazione dettagliata degli errori

        Args:
            filepath: Percorso del file da validare

        Raises:
            FileValidationError: Se la validazione del file fallisce
        """
        self._log_verbose(f"Avvio validazione del file di input per: {filepath}")

        if not filepath:
            raise FileValidationError("Nessun file specificato")

        path_obj = Path(filepath)

        # Controlla estensione del file
        if path_obj.suffix.lower() != ".json":
            raise FileValidationError("Il file deve avere estensione .json")

        # Controlla esistenza del file
        if not path_obj.exists():
            raise FileValidationError(f"File non trovato: {filepath}")

        # Controlla permessi di lettura
        if not os.access(filepath, os.R_OK):
            raise FileValidationError(f"Il file '{filepath}' non è leggibile")

        # Controlla dimensione del file
        file_size = path_obj.stat().st_size
        max_bytes = self.config.max_size_mb * 1024 * 1024
        if file_size > max_bytes:
            raise FileValidationError(f"File troppo grande ({file_size} byte > {max_bytes} byte limite)")

        self._log_verbose(f"Validazione del file avvenuta con successo: {filepath} ({file_size} byte)")

    def _validate_format(self, value: Any, pattern: re.Pattern, format_name: str) -> bool:
        """
        Validatore di formato generico con gestione errori

        Args:
            value: Valore da validare
            pattern: Pattern regex compilato
            format_name: Nome del formato per il logging

        Returns:
            True se il formato è valido, False altrimenti
        """
        if not isinstance(value, str):
            self._log_verbose(f"Validazione {format_name} fallita: non è una stringa")
            return False

        is_valid = bool(pattern.match(value))
        if not is_valid:
            self._log_verbose(f"Validazione {format_name} fallita per il valore: {value}")

        return is_valid

    def validate_purl(self, purl: Any) -> bool:
        """Valida il formato PURL"""
        return self._validate_format(purl, RegexPatterns.PURL, "PURL")

    def validate_swid(self, swid: Any) -> bool:
        """Valida il formato SWID"""
        return self._validate_format(swid, RegexPatterns.SWID, "SWID")

    def validate_swhid(self, swhid: Any) -> bool:
        """Valida il formato SWHID"""
        return self._validate_format(swhid, RegexPatterns.SWHID, "SWHID")

    def validate_cpe(self, cpe: Any) -> bool:
        """
        Valida il formato del campo CPE (supporta sia la v2.2 che la v2.3)

        Args:
            cpe: Valore del campo CPE da validare

        Returns:
            True se il formato del campo CPE è valido, False altrimenti
        """
        if not isinstance(cpe, str):
            return False

        return (bool(RegexPatterns.CPE_2_3.match(cpe)) or
                bool(RegexPatterns.CPE_2_2.match(cpe)))

    def validate_schema(self, file_handle: IO) -> bool:
        """
        Valida il file SBOM contro lo schema CycloneDX v1.6.  Vengono raccolti gli eventuali errori riscontrati

        Args:
            file_handle: Handle del file aperto posizionato all'inizio

        Returns:
            True se lo schema è valido, False altrimenti
        """
        self._log_verbose("Avvio validazione dello schema CycloneDX v1.6")

        try:
            file_handle.seek(0)
            sbom_content = file_handle.read()

            validator = JsonStrictValidator(SchemaVersion.V1_6)
            errors_iter = validator.validate_str(sbom_content, all_errors=True)

            # Il validatore CycloneDX restituisce None quando valido, iterator quando invalido
            if errors_iter is not None:
                errors = list(errors_iter)
                self._add_output_line(f"{OutputFormat.WARNING} La SBOM non è valida rispetto allo schema CycloneDX v1.6. Errori riscontrati:")
                for error in errors:
                    self._add_output_line(f" - {error}")
                return False

            self._log_verbose("Validazione della SBOM secondo lo schema CycloneDX v1.6 avvenuta con successo")
            return True

        except Exception as e:
            self._add_output_line(f"{OutputFormat.WARNING} Validazione dello schema CycloneDX v1.6 fallita: {e}")
            return False

    def validate_metadata_component(self, sbom_data: Dict[str, Any]) -> bool:
        """
        Valida presenza e struttura di metadata.component con messaggi di errore

        Args:
            sbom_data: Dati SBOM analizzati

        Returns:
            True se metadata.component è valorizzato, False altrimenti
        """
        self._log_verbose("Avvio validazione del componente 'metadata'")

        if not isinstance(sbom_data, dict):
            self._add_output_line(f"{OutputFormat.ERROR} La SBOM non è un oggetto JSON valido")
            return False

        metadata = sbom_data.get("metadata")
        if metadata is None:
            self._add_output_line(f"{OutputFormat.ERROR} Il campo 'metadata' non è presente nella SBOM")
            return False

        if not isinstance(metadata, dict):
            self._add_output_line(f"{OutputFormat.ERROR} Il campo 'metadata' non è un oggetto valido")
            return False

        if "component" not in metadata:
            self._add_output_line(f"{OutputFormat.ERROR} il campo 'metadata' è stato trovato, ma risulta mancante il campo 'component' al suo interno")
            return False

        component = metadata["component"]
        if not isinstance(component, dict):
            self._add_output_line(f"{OutputFormat.ERROR} 'metadata.component' non è un oggetto valido")
            return False

        self._add_output_line(f"{OutputFormat.SUCCESS} Il campo 'metadata.component' è presente nella SBOM")
        self._log_verbose("Validazione componente metadata completata con successo")
        return True

    def _check_address_country(self, entity: Dict[str, Any], role: str) -> bool:
        """
        Validazione delle informazioni SBOM relative alla provenienza geografica del componente

        Args:
            entity: Oggetto entità contenente informazioni sulla provenienza geografica del componente
            role: Nome ruolo (e.g. provider/manufacturer/supplier)

        Returns:
            True se il paese è valido e in whitelist
        """
        if not isinstance(entity, dict):
            self._add_output_line(f"{OutputFormat.ERROR} {role} non è un oggetto valido")
            return False

        address = entity.get("address", {})
        if not isinstance(address, dict):
            self._add_output_line(f"{OutputFormat.ERROR} {role} non ha al suo interno il campo 'address' valorizzato correttamente")
            return False

        country = address.get("country")
        if not country:
            self._add_output_line(f"{OutputFormat.ERROR} {role} non ha al suo interno il campo 'country'")
            return False

        country_upper = country.upper()
        if country_upper not in WHITELISTED_COUNTRIES:
            self._add_output_line(f"{OutputFormat.ERROR} Campo '{role}.address.country' valorizzato con il codice paese: '{country}'. Il codice paese non corrisponde a uno dei paesi in whitelist")
            return False

        self._add_output_line(f"{OutputFormat.SUCCESS} Validazione del campo '{role}.address.country' avvenuta con successo. Paese rilevato: {country}")
        return True

    def _validate_element_fields(self, element: Dict[str, Any], element_name: str,
                                required_fields: frozenset, roles: frozenset) -> bool:
        """
        Validazione campi

        Args:
            element: Elemento da validare
            element_name: Nome elemento per il logging
            required_fields: Set di campi obbligatori
            roles: Set di ruoli da validare

        Returns:
            True se tutte le validazioni passano
        """
        self._log_verbose(f"Validazione dei campi minimi per l'elemento: {element_name}")

        # Controlla campi obbligatori
        missing_fields = required_fields - element.keys()
        if missing_fields:
            for field in missing_fields:
                self._add_output_line(f"{OutputFormat.ERROR} Campo obbligatorio mancante: {field}")

        # Valida ruoli
        valid_roles = []
        for role in roles:
            entity = element.get(role)
            if isinstance(entity, dict):
                url_valid = "url" in entity
                name_valid = "name" in entity
                country_valid = self._check_address_country(entity, role)

                if not url_valid:
                    self._add_output_line(f"{OutputFormat.ERROR} {role.capitalize()} campo 'url' non presente")
                if not name_valid:
                    self._add_output_line(f"{OutputFormat.ERROR} {role.capitalize()} campo 'name' non presente")

                if url_valid and name_valid and country_valid:
                    valid_roles.append(role)

        # Risultato validazione complessiva
        all_required_present = len(missing_fields) == 0
        all_roles_valid = len(valid_roles) == len(roles)

        return all_required_present and all_roles_valid

    def validate_elements(self, elements: List[Dict[str, Any]], element_type: str,
                         required_fields: frozenset, roles: frozenset) -> List[Tuple[str, int]]:
        """
        Validazione elementi ottimizzata con elaborazione batch

        Args:
            elements: Lista di elementi da validare
            element_type: Nome tipo per il logging (component/service)
            required_fields: Campi obbligatori per questo tipo di elemento
            roles: Ruoli obbligatori per questo tipo di elemento

        Returns:
            Lista di elementi validi come tuple (nome, indice)
        """
        self._log_verbose(f"Avvio validazione di {len(elements)} {element_type}s")

        valid_elements = []

        for idx, element in enumerate(elements, 1):
            element_name = element.get('name', f'[{element_type} senza nome]')
            self._add_output_line(f"{element_type} {idx}: {element_name}")

            if self._validate_element_fields(element, element_name, required_fields, roles):
                self._add_output_line(f"{OutputFormat.SUCCESS} Tutti i campi minimi sono presenti")
                valid_elements.append((element.get("name"), idx))

            self._add_output_line(OutputFormat.ROW_SEP)

        self._log_verbose(f"Validazione completata: {len(valid_elements)} {element_type}s validi su {len(elements)}")
        return valid_elements

    def _validate_additional_field(self, element: Dict[str, Any], field_name: str,
                                   validator_func, element_type: str) -> bool:
        """
        Valida un singolo campo ulteriore con validatore appropriato

        Args:
            element: Elemento contenente il campo
            field_name: Nome del campo da validare
            validator_func: Funzione di validazione da utilizzare
            element_type: Tipo di elemento per il logging

        Returns:
            True se il campo è valido
        """
        if field_name not in element:
            return False

        field_value = element[field_name]
        if validator_func(field_value):
            self._add_output_line(f" {OutputFormat.SUCCESS} Il formato {field_name.upper()} è valido")
            return True
        else:
            self._add_output_line(f" {OutputFormat.ERROR} Il formato {field_name.upper()} non è valido: {field_value}")
            return False

    def check_additional_fields(self, elements: List[Dict[str, Any]], element_type: str,
                               additional_fields: frozenset) -> Dict:
        """
        Validazione campi ulteriori con raccolta statistiche

        Args:
            elements: Lista di elementi da controllare
            element_type: Tipo di elementi (component/service)
            additional_fields: Set di campi ulteriori

        Returns:
            Tupla contenente statistiche dei campi
        """
        self._log_verbose(f"Avvio verifica della presenza di campi ulteriori per {len(elements)} {element_type}s")

        merged = ADDITIONAL_COMPONENT_FIELDS.union(ADDITIONAL_SERVICE_FIELDS)
        stats = dict.fromkeys(merged, 0)
        stats = {"has_additional_fields": False, **stats}

        # Mapping validatori di campo
        validators = {
            'swid': self.validate_swid,
            'swhid': self.validate_swhid,
            'cpe': self.validate_cpe,
            'purl': self.validate_purl
        }

        for idx, element in enumerate(elements, 1):
            element_name = element.get('name', f'[{element_type} senza nome]')
            self._add_output_line(f"{element_type} {idx}: {element_name}")

            # Controlla presenza di campi raccomandati
            present_fields = additional_fields.intersection(element.keys())
            if present_fields:
                stats['has_additional_fields'] = True
                for field in present_fields:
                    self._add_output_line(f"Campo ulteriore trovato nella SBOM: {field}")

            # Valida campi specifici in base al tipo di elemento
            if element_type == 'component':
                # Valida campi specifici del formato
                for field, validator in validators.items():
                    if self._validate_additional_field(element, field, validator, element_type):
                        stats[f'{field}'] += 1

                # Gestisci campo hashes
                if 'hashes' in element:
                    self._add_output_line("Algoritmi hash e formati sono validi se la validazione dello schema CycloneDX v1.6 è avvenuta con successo")
                    stats['hashes'] += 1

            elif element_type == 'service':
                # Gestisci campo description specifico per servizi
                if 'description' in element:
                    self._add_output_line("Il campo 'description' è valorizzato come segue:")
                    self._add_output_line(f"  - {str(element['description'])}")
                    stats['description'] += 1

            # Gestisci campi comuni (properties, externalReferences)
            self._handle_common_fields(element, stats)

            self._add_output_line(OutputFormat.ROW_SEP)

        # Converti dict stats di nuovo in tupla per compatibilità
        return stats

    def _handle_common_fields(self, element: Dict[str, Any], stats: Dict[str, Any]) -> None:
        """
        Gestisce la validazione di campi comuni (properties, externalReferences)

        Args:
            element: Elemento da elaborare
            stats: Dizionario statistiche da aggiornare
        """
        # Gestisci properties
        properties = element.get("properties")
        if properties and isinstance(properties, list):
            stats['properties'] += 1
            self._add_output_line("Il campo 'properties' è valorizzato come segue:")
            for prop in properties:
                if isinstance(prop, dict):
                    name = prop.get('name', 'senza nome')
                    value = prop.get('value', 'nessun valore')
                    self._add_output_line(f"  - {name}: {value}")

        # Gestisci riferimenti esterni
        references = element.get("externalReferences")
        if references and isinstance(references, list):
            stats['externalReferences'] += 1
            self._add_output_line("Il campo 'externalReferences' è valorizzato come segue:")
            for ref in references:
                if isinstance(ref, dict):
                    ref_type = ref.get("type", "sconosciuto")
                    url = ref.get("url", "nessun URL fornito")
                    comment = ref.get("comment", "")
                    self._add_output_line(f"  - Tipo: {ref_type}")
                    self._add_output_line(f"    URL: {url}")
                    if comment:
                        self._add_output_line(f"    Commento: {comment}")

    def generate_summary(self, results: ValidationResults) -> None:
        """
        Genera un riepilogo di validazione completo con statistiche

        Args:
            results: Oggetto ValidationResults contenente tutti i dati di validazione
        """
        self._log_verbose("Generazione report riepilogo finale")

        self._add_output_line(OutputFormat.BLOCK_SEP)
        self._add_output_line("Riepilogo finale validazione e analisi SBOM (schema CycloneDX v1.6):")

        # Risultato validazione schema
        if results.schema_skipped:
            self._add_output_line("  - Validazione schema CycloneDX v1.6: NON EFFETTUATA su richiesta utente")
        else:
            status = "VALIDO" if results.schema_valid else "INVALIDO"
            self._add_output_line(f"  - Validazione dello schema CycloneDX v1.6: {status}")

        # Validazione metadata
        metadata_status = "COMPLETATA" if results.metadata_valid else "FALLITA"
        self._add_output_line(f"  - Validazione metadata SBOM: {metadata_status}")

        # Riepilogo componenti
        self._generate_element_summary("components", results.components_total, results.valid_components)

        # Riepilogo servizi
        self._generate_element_summary("services", results.services_total, results.valid_services)

        # Risultato validazione complessiva
        overall_success = self._determine_overall_success(results)

        if overall_success:
            status_msg = "NON EFFETTUATA" if results.schema_skipped else "COMPLETATA CON SUCCESSO"
            schema_note = " (validazione dello schema non effettuata)" if results.schema_skipped else ""
            self._add_output_line(f"{OutputFormat.SUCCESS} Validazione e analisi SBOM {status_msg}{schema_note}\n")
        else:
            self._add_output_line(f"{OutputFormat.ERROR} Validazione e analisi SBOM: come sopra riportato, sono state riscontrate non conformità rispetto a quanto descritto nelle linee guida ACN-ANAC per l'attribuzione dei criteri di premialità.\n")

        # Genera statistiche dettagliate dei campi
        self._generate_field_statistics(results)

    def _generate_element_summary(self, element_type: str, total: int, valid: List[Tuple[str, int]]) -> None:
        """Genera un riepilogo per un tipo di elemento specifico"""
        self._add_output_line(f"  - Numero di elementi di tipo '{element_type}' presenti nella SBOM: {total}")

        if total > 0:
            missing = total - len(valid)
            if missing > 0:
                self._add_output_line(f"  - Elementi di tipo '{element_type}' che non presentano i campi minimi richiesti: {missing}")
            else:
                self._add_output_line(f"  - Tutti gli elementi di tipo '{element_type}' hanno i campi minimi richiesti per l'assegnazione del punteggio di premialità")

    def _determine_overall_success(self, results: ValidationResults) -> bool:
        """Determina se la validazione complessiva è stata completata con successo"""
        return (
            len(results.valid_components) == results.components_total and
            len(results.valid_services) == results.services_total and
            (results.schema_valid or results.schema_skipped) and
            results.metadata_valid and
            (results.components_total > 0 or results.services_total > 0)
        )

    def _generate_field_statistics(self, results: ValidationResults) -> None:
        """Genera statistiche dettagliate per i campi ulteriori"""
        # Statistiche campi componenti
        if results.component_stats["has_additional_fields"] and results.components_total > 0:
            self._add_output_line("\nCampi ulteriori rilevati per elementi di tipo 'components':")
            self._generate_component_stats(results.component_stats, results.components_total)

        # Statistiche campi servizi
        if results.service_stats["has_additional_fields"] and results.services_total > 0:
            self._add_output_line("\nCampi ulteriori rilevati per elementi di tipo 'services':")
            self._generate_service_stats(results.service_stats, results.services_total)

    def _generate_component_stats(self, stats: Dict, total: int) -> None:
        """Genera statistiche relative ai campi ulteriori per elementi di tipo 'component'"""
        for i, field_name in enumerate(sorted(ADDITIONAL_COMPONENT_FIELDS), 1):
            count = stats[field_name]
            percentage = (count * 100) / total
            self._add_output_line(f"  - Campi '{field_name}' rilevati: {count} di {total} componenti ({percentage:.2f}%)")

    def _generate_service_stats(self, stats: Dict, total: int) -> None:
        """Genera statistiche relative ai campi ulteriori per elementi di tipo 'services'"""
        for i, field_name in enumerate(sorted(ADDITIONAL_SERVICE_FIELDS),1):
            count = stats[field_name]
            percentage = (count * 100) / total
            self._add_output_line(f"  - Campi '{field_name}' rilevati: {count} di {total} servizi ({percentage:.2f}%)")

    def write_report(self, filepath: str, results: ValidationResults) -> str:
        """
        Scrive report di validazione completo su file

        Args:
            filepath: Percorso file SBOM originale
            results: Risultati validazione

        Returns:
            Percorso del file report generato
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Determina directory di output
        if self.config.output_dir:
            base_dir = Path(self.config.output_dir)
            base_dir.mkdir(parents=True, exist_ok=True)
        else:
            base_dir = Path(filepath).parent

        report_path = base_dir / f"SBOM_Report_Analisi_{timestamp}.txt"

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                # Scrivi intestazione con metadata
                f.write(f"Report di Analisi validazione SBOM - {timestamp}\n")
                f.write(f"{'=' * 60}\n")
                f.write(f"File sorgente analizzato: {filepath}\n")
                f.write(f"Parametri di analisi:\n")
                f.write(f"  - Dimensione massima file: {self.config.max_size_mb}MB\n")
                f.write(f"  - Directory output: {base_dir}\n")
                f.write(f"  - Salta validazione schema: {self.config.skip_schema}\n")
                f.write(f"  - Modalità verbose: {self.config.verbose}\n")
                f.write(f"  - Modalità silenziosa: {self.config.quiet}\n")
                f.write(f"  - Tempo di elaborazione: {results.processing_time:.2f} secondi\n")
                f.write(f"{'=' * 60}\n\n")

                # Scrivi risultati validazione
                for line in self.output_lines:
                    f.write(f"{line}\n")

            self._log_verbose(f"Report scritto con successo in: {report_path}")
            return str(report_path)

        except Exception as e:
            raise SBOMValidationError(f"Fallimento nella scrittura del report: {e}")

    def validate_sbom_file(self, filepath: str) -> ValidationResults:
        """
        Funzione di validazione che orchestra l'intero processo di validazione SBOM

        Args:
            filepath: Percorso del file SBOM da validare

        Returns:
            Oggetto ValidationResults con dati di validazione completi
        """
        start_time = datetime.now()
        results = ValidationResults()

        try:
            # Step 1: Validazione file di input
            self._log_info("🔍 Avvio validazione e analisi del file SBOM...")
            self.validate_input_file(filepath)

            # Step 2: Carica e analizza JSON
            with self._file_reader(filepath) as file_handle:
                try:
                    sbom_data = json.load(file_handle)
                    self._log_info(f"{OutputFormat.SUCCESS} JSON caricato con successo\n")
                except json.JSONDecodeError as e:
                    raise SBOMValidationError(f"Formato JSON invalido: {e}")

                # Step 3: Validazione schema
                self._add_output_line(f"\n{OutputFormat.BLOCK_SEP}")
                self._add_output_line("Passo 1 - Validazione Schema CycloneDX v1.6:")

                if self.config.skip_schema:
                    results.schema_valid = True  # Assume valido quando saltato
                    results.schema_skipped = True
                    self._add_output_line(f"{OutputFormat.WARNING} Validazione schema NON EFFETTUATA su richiesta utente")
                else:
                    results.schema_valid = self.validate_schema(file_handle)
                    if results.schema_valid:
                        self._add_output_line(f"{OutputFormat.SUCCESS} Validazione dello schema SBOM completata con successo")

                self._add_output_line(f"{OutputFormat.BLOCK_SEP}\n")

            # Step 4: Validazione metadata
            self._add_output_line(f"{OutputFormat.BLOCK_SEP}")
            self._add_output_line("Step 2 - Validazione dei metadati della SBOM:")
            results.metadata_valid = self.validate_metadata_component(sbom_data)
            if results.metadata_valid:
                self._add_output_line(f"{OutputFormat.SUCCESS} Validazione 'metadata.component' completata con successo")
            self._add_output_line(f"{OutputFormat.BLOCK_SEP}\n")

            # Step 5: Validazione componenti
            self._validate_components(sbom_data, results)

            # Step 6: Validazione servizi
            self._validate_services(sbom_data, results)

            # Step 7: Validazione campi ulteriori
            self._validate_additional_fields(sbom_data, results)

            # Step 8: Genera riepilogo finale
            self.generate_summary(results)

            # Registra tempo di elaborazione
            results.processing_time = (datetime.now() - start_time).total_seconds()

            return results

        except Exception as e:
            self._add_output_line(f"{OutputFormat.ERROR} Validazione fallita: {str(e)}")
            results.processing_time = (datetime.now() - start_time).total_seconds()
            return results

    def _validate_components(self, sbom_data: Dict[str, Any], results: ValidationResults) -> None:
        """Valida sezione 'components' della SBOM"""
        self._add_output_line(f"{OutputFormat.BLOCK_SEP}")
        self._add_output_line("Passo 3: Validazione dei campi minimi per elementi di tipo 'components':")
        self._add_output_line(OutputFormat.ROW_SEP)

        components = sbom_data.get("components", [])
        if not isinstance(components, list):
            self._add_output_line(f"{OutputFormat.ERROR} 'components' dovrebbe essere una lista")
            return

        results.components_total = len(components)

        if components:
            results.valid_components = self.validate_elements(
                components, "component", MINIMUM_COMPONENT_FIELDS, COMPONENT_ROLES
            )
        else:
            self._add_output_line("Nessun elemento di tipo 'components' riscontrato nella SBOM")

        self._add_output_line(f"{OutputFormat.BLOCK_SEP}\n")

    def _validate_services(self, sbom_data: Dict[str, Any], results: ValidationResults) -> None:
        """Valida sezione servizi della SBOM"""
        self._add_output_line(f"{OutputFormat.BLOCK_SEP}")
        self._add_output_line("Step 4: Validazione dei campi minimi per elementi di tipo 'services':")
        self._add_output_line(OutputFormat.ROW_SEP)

        services = sbom_data.get("services", [])
        if not isinstance(services, list):
            self._add_output_line(f"{OutputFormat.ERROR} l'elemento 'services' dovrebbe essere una lista")
            return

        results.services_total = len(services)

        if services:
            results.valid_services = self.validate_elements(
                services, "service", MINIMUM_SERVICE_FIELDS, SERVICE_ROLES
            )
        else:
            self._add_output_line("Nessun elemento di tipo 'services' riscontrato nella SBOM")

        self._add_output_line(f"{OutputFormat.BLOCK_SEP}\n")

    def _validate_additional_fields(self, sbom_data: Dict[str, Any], results: ValidationResults) -> None:
        """Valida campi ulteriori per componenti e servizi"""
        # Validazione campi aggiuntivi componenti
        self._add_output_line(f"{OutputFormat.BLOCK_SEP}")
        self._add_output_line("Step 5: Validazione dei campi ulteriori per elementi di tipo 'components':")

        components = sbom_data.get("components", [])
        results.component_stats = self.check_additional_fields(
            components, "component", ADDITIONAL_COMPONENT_FIELDS
        )

        if not results.component_stats["has_additional_fields"]:
            self._add_output_line("Nessun campo ulteriore riscontrato per elementi di tipo 'components'")
        self._add_output_line(f"{OutputFormat.BLOCK_SEP}\n")

        # Validazione campi aggiuntivi servizi
        self._add_output_line(f"{OutputFormat.BLOCK_SEP}")
        self._add_output_line("Step 6: Validazione dei campi ulteriori per elementi di tipo 'services':")

        services = sbom_data.get("services", [])
        results.service_stats = self.check_additional_fields(
            services, "service", ADDITIONAL_SERVICE_FIELDS
        )

        if not results.service_stats["has_additional_fields"]:
            self._add_output_line("Nessun campo ulteriore riscontrato per elementi di tipo 'services'")
        self._add_output_line(f"{OutputFormat.BLOCK_SEP}\n")

# =================================================================================
# PARSING ARGOMENTI CLI
# =================================================================================

def setup_argument_parser() -> argparse.ArgumentParser:
    """
    Configura e restituisce parser degli argomenti CLI ottimizzato

    Returns:
        Istanza ArgumentParser configurata
    """
    parser = argparse.ArgumentParser(
        description='Analizzatore e Validatore SBOM Ottimizzato per CycloneDX v1.6',
        epilog='''
Esempi utilizzo:
  %(prog)s sbom.json
  %(prog)s sbom.json --max-size 50 --output-dir ./reports --verbose
  %(prog)s sbom.json --quiet
  %(prog)s sbom.json --skip-schema --verbose
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'input_file',
        help='File SBOM in formato JSON da analizzare'
    )

    parser.add_argument(
        '--max-size',
        type=int,
        default=20,
        metavar='MB',
        help='Dimensione massima file SBOM in MB (default: 20)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        metavar='DIR',
        help='Directory per salvare il report di analisi (default: stessa directory del file di input)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modalità verbose: mostra informazioni aggiuntive durante l\'analisi'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Modalità silenziosa: riduce output console (solo errori)'
    )

    parser.add_argument(
        '--skip-schema',
        action='store_true',
        help='Salta validazione schema CycloneDX v1.6 (non raccomandato)'
    )

    return parser

def create_config_from_args(args: argparse.Namespace) -> ValidationConfig:
    """
    Crea ValidationConfig dagli argomenti della riga di comando analizzati

    Args:
        args: Argomenti riga di comando analizzati

    Returns:
        Oggetto ValidationConfig

    Raises:
        ValueError: Se gli argomenti sono mutuamente esclusivi o invalidi
    """
    if args.verbose and args.quiet:
        raise ValueError("Le opzioni --verbose e --quiet sono mutuamente esclusive")

    # Determina livello di validazione
    if args.verbose:
        level = ValidationLevel.VERBOSE
    elif args.quiet:
        level = ValidationLevel.QUIET
    else:
        level = ValidationLevel.NORMAL

    return ValidationConfig(
        max_size_mb=args.max_size,
        output_dir=args.output_dir,
        verbose=args.verbose,
        quiet=args.quiet,
        skip_schema=args.skip_schema,
        validation_level=level
    )

# =================================================================================
# ESECUZIONE PRINCIPALE
# =================================================================================

def main() -> None:
    """
    Funzione di esecuzione principale con gestione errori completa e tracciamento delle prestazioni

    Questa funzione orchestra l'intero processo di validazione SBOM:
    1. Analizza gli argomenti da riga di comando
    2. Crea istanza di validatore
    3. Esegue la validazione della SBOM
    4. Genera e salva il report di analisi
    5. Esce con un codice di stato appropriato
    """
    start_time = datetime.now()

    try:
        # Analizza argomenti riga di comando
        parser = setup_argument_parser()
        args = parser.parse_args()

        # Crea configurazione
        config = create_config_from_args(args)

        # Inizializza validatore
        validator = SBOMValidator(config)
        validator._log_verbose(f"Validatore inizializzato con configurazione: {config}")

        # Esegui validazione
        results = validator.validate_sbom_file(args.input_file)

        # Genera e salva report
        report_path = validator.write_report(args.input_file, results)

        # Output finale
        validator._log_info(f"📄 Report di analisi SBOM salvato in: {report_path}")
        validator._log_info("🔍 Analisi SBOM completata.")

        total_time = (datetime.now() - start_time).total_seconds()
        validator._log_info(f"⏱️ Tempo totale di validazione e elaborazione: {total_time:.2f} secondi")

        # Esci con successo
        sys.exit(0)

    except FileValidationError as e:
        print(f"{OutputFormat.ERROR} Errore validazione file: {e}")
        sys.exit(1)
    except SBOMValidationError as e:
        print(f"{OutputFormat.ERROR} Errore validazione SBOM: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"{OutputFormat.ERROR} Errore configurazione: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{OutputFormat.WARNING} Processo interrotto dall'utente")
        sys.exit(1)
    except Exception as e:
        print(f"{OutputFormat.ERROR} Errore inaspettato: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
