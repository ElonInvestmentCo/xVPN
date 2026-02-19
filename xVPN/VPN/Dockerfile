FROM python:3.11-slim

RUN apt-get update && apt-get install -y wireguard-tools iptables

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
