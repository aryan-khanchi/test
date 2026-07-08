import os
from typing import List

import yaml
from dotenv import dotenv_values
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULTS = {
    "port": 8000,
    "workers": 1,
    "debug": False,
    "log_level": "info",
    "api_key": "default-secret-000",
}

def coerce_value(key: str, value):
    if key in {"port", "workers"}:
        return int(value)
    if key == "debug":
        return str(value).strip().lower() in {"true", "1", "yes", "on"}
    return str(value)

def load_yaml_layer():
    try:
        with open("config.development.yaml", "r") as f:
            data = yaml.safe_load(f) or {}
            return data
    except FileNotFoundError:
        return {}

def load_dotenv_layer():
    raw = dotenv_values(".env")
    data = {}

    for key, value in raw.items():
        if value is None:
            continue
        if key == "APP_API_KEY":
            data["api_key"] = value
        elif key == "NUM_WORKERS":
            data["workers"] = value

    return data

def load_os_env_layer():
    data = {}
    for key, value in os.environ.items():
        if not key.startswith("APP_"):
            continue

        short_key = key.removeprefix("APP_").lower()

        if short_key == "api_key":
            data["api_key"] = value
        else:
            data[short_key] = value

    return data

def merge_layer(base: dict, layer: dict):
    for key, value in layer.items():
        base[key] = coerce_value(key, value)
    return base

@app.get("/effective-config")
async def effective_config(request: Request, set: List[str] = Query(default=[])):
    config = dict(DEFAULTS)

    config = merge_layer(config, load_dotenv_layer())
    config = merge_layer(config, load_yaml_layer())
    config = merge_layer(config, load_os_env_layer())

    for item in set:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        config[key] = coerce_value(key, value)

    return {
        "port": config["port"],
        "workers": config["workers"],
        "debug": config["debug"],
        "log_level": config["log_level"],
        "api_key": "****",
    }
