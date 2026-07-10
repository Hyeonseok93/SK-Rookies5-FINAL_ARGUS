from inventory.schema import InputParam
from inventory.sources.openapi import _parameter_inputs


def test_ref_object_query_parameter_expands_one_level_into_properties():
    spec = {
        "components": {
            "schemas": {
                "CarSearchRequest": {
                    "type": "object",
                    "required": ["pickupDate", "returnTime"],
                    "properties": {
                        "pickupDate": {"type": "string", "format": "date", "example": "2026-07-03"},
                        "pickupTime": {"type": "string", "format": "time"},
                        "returnDate": {"type": "string", "format": "date"},
                        "returnTime": {"type": "string", "format": "date-time", "default": "10:00"},
                        "locationId": {"type": "integer"},
                    },
                }
            }
        }
    }
    operation = {
        "parameters": [
            {
                "name": "request",
                "in": "query",
                "schema": {"$ref": "#/components/schemas/CarSearchRequest"},
            }
        ]
    }

    inputs = _parameter_inputs(spec, operation)

    assert [item.name for item in inputs] == [
        "pickupDate",
        "pickupTime",
        "returnDate",
        "returnTime",
        "locationId",
    ]
    assert "request" not in {item.name for item in inputs}
    assert {item.name for item in inputs if item.required} == {
        "pickupDate",
        "returnTime",
    }
    assert next(item for item in inputs if item.name == "locationId").type == "integer"
    assert next(item for item in inputs if item.name == "returnTime").sample == "10:00"
    assert {item.name: item.format for item in inputs} == {
        "pickupDate": "date",
        "pickupTime": "time",
        "returnDate": "date",
        "returnTime": "date-time",
        "locationId": None,
    }


def test_input_param_format_survives_serialization_and_old_data_still_loads():
    original = InputParam(in_="query", name="pickupDate", format="date")
    encoded = original.to_dict()

    assert encoded["format"] == "date"
    assert InputParam.from_dict(encoded).format == "date"
    assert InputParam.from_dict({"in": "query", "name": "legacy"}).format is None


def test_object_parameter_outside_query_remains_a_single_parameter():
    spec = {
        "components": {
            "schemas": {
                "HeaderObject": {
                    "type": "object",
                    "properties": {"nested": {"type": "string"}},
                }
            }
        }
    }
    operation = {
        "parameters": [
            {
                "name": "X-Context",
                "in": "header",
                "schema": {"$ref": "#/components/schemas/HeaderObject"},
            }
        ]
    }

    inputs = _parameter_inputs(spec, operation)

    assert [(item.in_, item.name, item.type) for item in inputs] == [
        ("header", "X-Context", "object")
    ]
