from inventory.merge import merge_trees
from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta


def _tree(endpoint: Endpoint) -> ApiTree:
    return ApiTree(meta=InventoryMeta(), endpoints=[endpoint])


def test_localhost_aliases_merge_and_preserve_request_param_union():
    first = Endpoint(
        method="GET",
        path="/api/v1/cars/search",
        base_url="http://127.0.0.1:8080",
        request_params=[
            InputParam(in_="query", name="pickupDate"),
            InputParam(in_="query", name="returnDate"),
        ],
    )
    second = Endpoint(
        method="GET",
        path="/api/v1/cars/search",
        base_url="http://localhost:8080",
        request_params=[
            InputParam(in_="query", name="returnDate"),
            InputParam(in_="query", name="returnTime"),
        ],
    )

    merged = merge_trees([_tree(first), _tree(second)])

    assert len(merged.endpoints) == 1
    assert merged.endpoints[0].endpoint_id == (
        "http://localhost:8080:GET:/api/v1/cars/search"
    )
    assert {param.name for param in merged.endpoints[0].request_params} == {
        "pickupDate",
        "returnDate",
        "returnTime",
    }


def test_merge_preserves_format_from_openapi_input():
    first = InputParam(in_="query", name="pickupDate", sources=["probe"])
    second = InputParam(in_="query", name="pickupDate", format="date", sources=["openapi"])

    from inventory.merge import merge_inputs

    assert merge_inputs([first], [second])[0].format == "date"
