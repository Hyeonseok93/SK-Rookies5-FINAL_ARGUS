from inventory.schema import Endpoint, InputParam
from inventory_bridge import endpoints_to_scan_targets


def test_duplicate_scan_targets_preserve_parameter_union(monkeypatch):
    monkeypatch.setattr("inventory_bridge.probe_url", lambda value: value)
    endpoints = [
        Endpoint(
            method="GET",
            path="/api/v1/cars/search",
            base_url="http://localhost:8080",
            request_params=[InputParam(in_="query", name="pickupDate")],
        ),
        Endpoint(
            method="GET",
            path="/api/v1/cars/search",
            base_url="http://localhost:8080",
            request_params=[InputParam(in_="query", name="returnTime")],
        ),
    ]

    targets = endpoints_to_scan_targets(endpoints)

    assert len(targets) == 1
    assert {param.name for param in targets[0].params} == {
        "pickupDate",
        "returnTime",
    }


def test_inventory_format_reaches_scan_param_schema(monkeypatch):
    monkeypatch.setattr("inventory_bridge.probe_url", lambda value: value)
    endpoint = Endpoint(
        method="GET",
        path="/api/v1/cars/search",
        base_url="http://localhost:8080",
        request_params=[
            InputParam(in_="query", name="pickupDate", format="date"),
            InputParam(in_="query", name="returnTime", format="date-time"),
        ],
    )

    target = endpoints_to_scan_targets([endpoint])[0]
    assert {param.name: param.schema["format"] for param in target.params} == {
        "pickupDate": "date",
        "returnTime": "date-time",
    }
