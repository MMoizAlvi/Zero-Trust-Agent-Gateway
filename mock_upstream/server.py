from fastapi import FastAPI, Request
import uvicorn

app = FastAPI(title="Protected Internal Services API")

@app.get("/api/v1/metrics")
async def get_metrics(request: Request):
    agent = request.headers.get("X-Authenticated-Agent", "Unknown")
    return {"status": "success", "data": "System operational", "accessed_by": agent}

@app.post("/api/v1/execute-transaction")
async def execute_transaction(request: Request):
    data = await request.json()
    agent = request.headers.get("X-Authenticated-Agent", "Unknown")
    return {
        "status": "success",
        "message": f"Transaction of ${data.get('amount')} processed successfully",
        "executed_by": agent
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)