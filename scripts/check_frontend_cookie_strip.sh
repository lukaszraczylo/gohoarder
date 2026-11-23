#!/bin/sh
# Builds the frontend image from a Dockerfile and checks that /api and /ws do not forward the
# browser's Cookie header to the backend. Usage: scripts/check_frontend_cookie_strip.sh [Dockerfile]
set -eu

dockerfile="${1:-Dockerfile.frontend}"
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
tag="gohoarder-frontend-cookie-check:$$"
net="gohoarder-cookie-check-$$"
stub="$net-backend"
front="$net-frontend"

cleanup() {
	docker rm -f "$front" "$stub" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	docker rmi "$tag" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/frontend/dist"
echo '<html></html>' >"$work/frontend/dist/index.html"
cp "$root/$dockerfile" "$work/Dockerfile"
docker build -q --load -t "$tag" "$work" >/dev/null

cat >"$work/stub.conf" <<'CONF'
server {
    listen 8080;
    location / { default_type text/plain; return 200 "cookie=[$http_cookie]"; }
}
CONF

docker network create "$net" >/dev/null
docker run -d --name "$stub" --network "$net" -v "$work/stub.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
docker run -d --name "$front" --network "$net" -e BACKEND_HOST="$stub" -e BACKEND_PORT=8080 "$tag" >/dev/null

cookie="session=$(head -c 8000 /dev/zero | tr '\0' 'a')"
status=0
for path in /api/packages /ws; do
	ok=no
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		body="$(docker exec "$front" wget -qO- --header "Cookie: $cookie" "http://127.0.0.1$path" 2>/dev/null || true)"
		[ -n "$body" ] && ok=yes && break
		sleep 1
	done
	if [ "$ok" = no ]; then
		echo "FAIL: $path returned no body"
		status=1
	elif [ "$body" = "cookie=[]" ]; then
		echo "ok: $path forwards no Cookie"
	else
		echo "FAIL: $path forwarded a Cookie header ($(printf '%s' "$body" | wc -c) bytes)"
		status=1
	fi
done
exit "$status"
