import random
import uuid

def safe_body(ep: dict) -> dict:
    body = {}
    for param in ep.get("request_params", []):
        if param.get("in") == "body":
            name = param.get("name", "")
            lower_name = name.lower()
            ptype = param.get("type", "string")
            pformat = param.get("format", "")
            
            # Determine base value based on Swagger Format and Name heuristics
            if ptype in {"integer", "number"}:
                val = random.randint(1, 1000)
            elif ptype == "boolean":
                val = True
            elif ptype == "array":
                val = ["test"]
            else: # string
                if pformat == "email" or "email" in lower_name:
                    val = f"tester_{random.randint(10000,99999)}@test.com"
                elif pformat == "password" or "password" in lower_name:
                    val = "ValidPass123!"
                elif pformat == "uuid" or "uuid" in lower_name:
                    val = str(uuid.uuid4())
                elif pformat == "date-time" or "date" in lower_name:
                    val = "2026-01-01T00:00:00Z"
                elif "phone" in lower_name or "tel" in lower_name:
                    val = f"010{random.randint(10000000, 99999999)}"
                elif "nickname" in lower_name or "name" in lower_name:
                    val = f"User_{random.randint(1000,9999)}"
                else:
                    val = f"test_str_{random.randint(1, 999)}"
            
            body[name] = val
            
    # Handle passwordConfirm constraints if both exist
    if "passwordConfirm" in body and "password" in body:
        body["passwordConfirm"] = body["password"]
        
    return body
