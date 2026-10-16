#!/usr/bin/env bash
# One-command synthetic lab-breach demo. Synthetic data only.
# SQL Server Developer Edition is licensed for development/test/demo use only; real cases restore to a
# SQL Server instance the hospital provides and licenses.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${TSCOPE_PYTHON:-/opt/tscope-venv/bin/python}"
ROWS="${ROWS:-100000}"
CONTAINER="${MSSQL_CONTAINER:-mssql-test}"
PORT="${MSSQL_PORT:-14330}"
export TSCOPE_DEMO_MSSQL_PASSWORD="${TSCOPE_DEMO_MSSQL_PASSWORD:-Synth3tic!Demo}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker start "$CONTAINER" >/dev/null
  else
    docker run -d --name "$CONTAINER" -e ACCEPT_EULA=Y -e MSSQL_PID=Developer \
      -e "MSSQL_SA_PASSWORD=$TSCOPE_DEMO_MSSQL_PASSWORD" -p "127.0.0.1:$PORT:1433" \
      mcr.microsoft.com/mssql/server:2022-latest >/dev/null
  fi
fi
echo "waiting for SQL Server ($CONTAINER)..."
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$TSCOPE_DEMO_MSSQL_PASSWORD" -C \
       -Q "set nocount on; select 1" -h -1 >/dev/null 2>&1; then break; fi
  sleep 3
done

exec "$PY" "$HERE/run_demo.py" --rows "$ROWS" --mssql-port "$PORT" --mssql-container "$CONTAINER" "$@"
