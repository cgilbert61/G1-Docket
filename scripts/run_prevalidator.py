import os
import uvicorn

os.environ["POD_PUBLIC_KEY_DIR"] = ".pod_public_keys"
from prevalidator.proxy import create_prevalidator_app

app = create_prevalidator_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=18082)
