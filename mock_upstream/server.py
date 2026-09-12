from fastapi import FastAPI, Request
import uvicorn

app = FastAPI(title="Mock Upstream Tool API")

@app.get("/api/analytics")
async def get_analytics(request: Request):
    agent_id = request.headers.get("X-Agent-ID", "Unknown")
    return {
        "status": "success",
        "data": "Analytics report data fetched successfully.",
        "executed_by": agent_id
    }

@app.post("/api/transaction")
async def execute_transaction(request: Request):
    data = await request.json()
    agent_id = request.headers.get("X-Agent-ID", "Unknown")
    return {
        "status": "success",
        "transaction_id": "TXN-994827",
        "amount_processed": data.get("amount"),
        "executed_by": agent_id
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
    