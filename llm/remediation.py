import json
import yaml
import ollama

DEFAULT_SEVERITY = {
    "password": "CRITICAL",
    "api_key": "HIGH",
    #"Slack_token": "MEDIUM",
    "generic": "LOW"
}

results = json.load(open("output/results.json"))

policy = yaml.safe_load(open("SECHA/policy.yml"))

#llm = Ollama(model = "llama3.1")


rotation_days = policy.get("rotation_days", 30)

def generate_rotation_plan(finding):
    prompt = f"""
you are a security remediation expert.
Create a JSON structured plan.

Finding:
{finding}

rotation_days: {rotation_days}

Return JSON with: action, rotation_window, recommended_storage, notes.
"""
    #response = llm.generate(prompt)
    response = ollama.generate(model="llama2:7b",prompt = prompt)

    return str(response)

plan = []
for f in results:
    severity = DEFAULT_SEVERITY.get(f["type"], "LOW")
    f["severity"] = severity
    recommendation = generate_rotation_plan(f)
    f["recommendation"] = recommendation
    plan.append(f)

with open("output/rotation_plan.json","w") as f:
    json.dump(plan, f, indent=4)

print("Rotation plan generatd in output/rotation_plan.json")
