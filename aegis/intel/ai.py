"""The AI stack: which products are self-hosted AI/ML services, how to recognise them passively, and which have CISA KEV entries.

Evidence types, strongest first: a KEV CVE on the host (InternetDB `vulns`) → a product CPE → a product hostname →
a port used almost only by that product. Ports 8888 (Jupyter) and 5000 (MLflow) are common for other software and
never count without product evidence.
"""
import re

# name, CPE vendor:product prefixes (InternetDB CPE 2.2 URI form), hostname pattern, KEV vendor/product pattern, default ports
AI_PRODUCTS = [
    ("LiteLLM", ["litellm:litellm", "berriai:litellm"], r"litellm", r"\blitellm\b|\bberriai\b", [4000]),
    ("Langflow", ["langflow:langflow", "langflow-ai:langflow", "ibm:langflow"], r"langflow", r"\blangflow\b", [7860]),
    ("MLflow", ["lfprojects:mlflow", "mlflow:mlflow", "databricks:mlflow"], r"mlflow", r"\bmlflow\b", [5000]),
    ("Ray", ["anyscale:ray", "ray-project:ray", "ray_project:ray"], r"\bray-?(dashboard|head|cluster|serve)\b", r"^ray-project\b|\banyscale\b", [8265, 10001]),
    ("n8n", ["n8n:n8n", "n8n-io:n8n"], r"\bn8n\b", r"\bn8n\b", [5678]),
    ("Ollama", ["ollama:ollama"], r"ollama", r"\bollama\b", [11434]),
    ("vLLM", ["vllm:vllm", "vllm-project:vllm"], r"\bvllm\b", r"\bvllm\b", []),
    ("Gradio", ["gradio_project:gradio", "gradio:gradio"], r"gradio", r"\bgradio\b", [7860]),
    ("Jupyter", ["jupyter:jupyter_server", "jupyter:notebook", "jupyter:jupyterhub", "jupyter:jupyterlab"], r"jupyter", r"\bjupyter\b", [8888]),
    ("Open WebUI", ["openwebui:open_webui", "open-webui:open-webui"], r"open-?webui", r"\bopen ?webui\b", []),
    ("Flowise", ["flowiseai:flowise"], r"flowise", r"\bflowise\b", []),
    ("ComfyUI", ["comfy:comfyui", "comfyanonymous:comfyui"], r"comfyui", r"\bcomfyui\b", [8188]),
    ("Qdrant", ["qdrant:qdrant"], r"qdrant", r"\bqdrant\b", [6333]),
    ("Milvus", ["milvus:milvus", "milvus-io:milvus"], r"milvus", r"\bmilvus\b", [19530]),
    ("Kubeflow", ["kubeflow:kubeflow"], r"kubeflow", r"\bkubeflow\b", []),
    ("NVIDIA Triton", ["nvidia:triton_inference_server"], r"\btriton\b", r"\btriton inference\b", []),
]
# ports that on their own point at an AI service (port-only evidence → Medium, "unconfirmed")
AI_PORTS = {11434: "Ollama", 8265: "Ray dashboard", 7860: "Gradio / Langflow", 6333: "Qdrant", 19530: "Milvus"}
# 10001 is also used by network gear (e.g. device discovery / serial-over-IP), so it needs product evidence like the others
AMBIGUOUS_PORTS = {8888: "Jupyter", 5000: "MLflow", 4000: "LiteLLM", 5678: "n8n", 8188: "ComfyUI", 10001: "Ray client"}

_HOST_RX = [(n, re.compile(h, re.I)) for n, _, h, _, _ in AI_PRODUCTS]
_KEV_RX = [(n, re.compile(k, re.I)) for n, _, _, k, _ in AI_PRODUCTS]
KEV_FILTER = re.compile("|".join(k for _, _, _, k, _ in AI_PRODUCTS), re.I)


def product_from_cpe(cpe: str) -> str | None:
    c = (cpe or "").lower().replace("cpe:/a:", "").replace("cpe:2.3:a:", "")
    for name, cpes, *_ in AI_PRODUCTS:
        if any(c.startswith(p) for p in cpes):
            return name
    return None


def product_from_host(host: str) -> str | None:
    labels = ".".join((host or "").lower().split(".")[:-2]) or host
    for name, rx in _HOST_RX:
        if rx.search(labels):
            return name
    return None


def kev_product(vendor: str, product: str) -> str | None:
    """Map a CISA KEV vendorProject/product to an AI product ('Ray-Project'/'Ray' → Ray; DrayTek never matches)."""
    s = f"{vendor or ''} {product or ''}".strip()
    for name, rx in _KEV_RX:
        if rx.search(s):
            return name
    return None


def assess_host(ports: list[int], cpes: list[str], hosts: list[str]) -> dict | None:
    """-> {"products": [...], "ports": [...], "evidence": "cpe|host|port"} for one IP, or None."""
    prods = {p for p in (product_from_cpe(c) for c in cpes or []) if p}
    ev = "cpe" if prods else None
    if not prods:
        prods = {p for p in (product_from_host(h) for h in hosts or []) if p}
        ev = "host" if prods else None
    ai_ports = [p for p in ports or [] if p in AI_PORTS]
    amb = [p for p in ports or [] if p in AMBIGUOUS_PORTS]
    if prods:
        return {"products": sorted(prods), "ports": sorted(set(ai_ports + amb)), "evidence": ev}
    if ai_ports:
        return {"products": [AI_PORTS[p] for p in ai_ports], "ports": ai_ports, "evidence": "port"}
    return None
