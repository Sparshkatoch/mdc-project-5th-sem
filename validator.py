"""
Input Validation Module for Incident Decision Engine.

Provides strict, defensive validation of incoming incident parameters
prior to evaluation by the rules engine.
"""

from typing import Any, Dict, List, Tuple


class ValidationError(Exception):
    """Raised when incident parameters fail validation rules."""

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_incident_input(data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], List[str]]:
    """
    Validates and normalizes raw incident input parameters.

    Expected input dictionary keys:
      - title (str): Non-empty title / description of the incident
      - incident_type (str): Type of incident (e.g. 'Phishing', 'Ransomware')
      - business_impact (str): 'Low', 'Medium', 'High', or 'Critical'
      - affected_assets (int or str): Positive integer >= 1
      - confidence (float or int or str): Numeric value between 0 and 100
      - persistence (bool or str): Boolean or 'Yes'/'No'
      - data_exposure (bool or str): Boolean or 'Yes'/'No'
      - analyst_notes (str, optional): Additional context

    Returns:
      (is_valid, normalized_data, error_messages)
    """
    errors: List[str] = []
    normalized: Dict[str, Any] = {}

    # 1. Title / Identifier validation
    title = data.get("title", "")
    if not isinstance(title, str) or not title.strip():
        errors.append("Incident Title / Name cannot be blank.")
    else:
        normalized["title"] = title.strip()

    # 2. Incident Type validation
    incident_type = data.get("incident_type", "")
    if not isinstance(incident_type, str) or not incident_type.strip():
        errors.append("Incident Type must be selected or provided.")
    else:
        normalized["incident_type"] = incident_type.strip()

    # 3. Business Impact validation
    valid_impacts = ["Low", "Medium", "High", "Critical"]
    impact_raw = data.get("business_impact", "")
    if not impact_raw:
        errors.append("Business Impact is required.")
    else:
        impact_normalized = str(impact_raw).strip().capitalize()
        if impact_normalized not in valid_impacts:
            errors.append(f"Business Impact '{impact_raw}' is invalid. Allowed: {valid_impacts}")
        else:
            normalized["business_impact"] = impact_normalized

    # 4. Affected Assets validation
    assets_raw = data.get("affected_assets", None)
    if assets_raw is None or str(assets_raw).strip() == "":
        errors.append("Affected Assets count is required.")
    else:
        try:
            assets_val = int(assets_raw)
            if assets_val < 1:
                errors.append(f"Affected Assets must be at least 1 (got {assets_val}).")
            elif assets_val > 1_000_000:
                errors.append(f"Affected Assets exceeds realistic enterprise threshold ({assets_val}).")
            else:
                normalized["affected_assets"] = assets_val
        except (ValueError, TypeError):
            errors.append(f"Affected Assets must be an integer (got '{assets_raw}').")

    # 5. Confidence validation (0 to 100)
    conf_raw = data.get("confidence", None)
    if conf_raw is None or str(conf_raw).strip() == "":
        errors.append("Confidence score is required.")
    else:
        try:
            conf_val = float(conf_raw)
            if conf_val < 0.0 or conf_val > 100.0:
                errors.append(f"Confidence score must be between 0.0 and 100.0% (got {conf_val}).")
            else:
                normalized["confidence"] = round(conf_val, 2)
        except (ValueError, TypeError):
            errors.append(f"Confidence score must be a number between 0 and 100 (got '{conf_raw}').")

    # 6. Persistence validation (Boolean or 'Yes'/'No')
    persistence_raw = data.get("persistence", None)
    if persistence_raw is None:
        errors.append("Persistence status is required.")
    elif isinstance(persistence_raw, bool):
        normalized["persistence"] = persistence_raw
    elif isinstance(persistence_raw, str):
        val_clean = persistence_raw.strip().lower()
        if val_clean in ["yes", "true", "1"]:
            normalized["persistence"] = True
        elif val_clean in ["no", "false", "0"]:
            normalized["persistence"] = False
        else:
            errors.append(f"Persistence must be Yes/No or True/False (got '{persistence_raw}').")
    else:
        errors.append(f"Persistence has invalid type ({type(persistence_raw).__name__}).")

    # 7. Data Exposure validation (Boolean or 'Yes'/'No')
    exposure_raw = data.get("data_exposure", None)
    if exposure_raw is None:
        errors.append("Data Exposure status is required.")
    elif isinstance(exposure_raw, bool):
        normalized["data_exposure"] = exposure_raw
    elif isinstance(exposure_raw, str):
        val_clean = exposure_raw.strip().lower()
        if val_clean in ["yes", "true", "1"]:
            normalized["data_exposure"] = True
        elif val_clean in ["no", "false", "0"]:
            normalized["data_exposure"] = False
        else:
            errors.append(f"Data Exposure must be Yes/No or True/False (got '{exposure_raw}').")
    else:
        errors.append(f"Data Exposure has invalid type ({type(exposure_raw).__name__}).")

    # 8. Analyst notes (optional)
    notes_raw = data.get("analyst_notes", "")
    normalized["analyst_notes"] = str(notes_raw).strip() if notes_raw else ""

    is_valid = len(errors) == 0
    return is_valid, normalized, errors
