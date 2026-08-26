"""Master Node entrypoint: uvicorn server for master.api:app."""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "master.api:app",
        host="0.0.0.0",
        port=8080,
        log_config=None,          # our JSON logging stays in charge
        access_log=False,
    )
