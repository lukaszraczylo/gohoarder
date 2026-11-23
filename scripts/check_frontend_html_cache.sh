#!/bin/sh
# Builds the frontend image from a Dockerfile and checks that the SPA HTML is revalidated on every
# load while hashed assets stay immutable. A cached index.html keeps old bundles after a deploy.
# Usage: scripts/check_frontend_html_cache.sh [Dockerfile]
set -eu

dockerfile="${1:-Dockerfile.frontend}"
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
tag="gohoarder-frontend-cache-check:$$"
front="gohoarder-cache-check-$$"

cleanup() {
	docker rm -f "$front" >/dev/null 2>&1 || true
	docker rmi "$tag" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/frontend/dist/assets"
echo '<html></html>' >"$work/frontend/dist/index.html"
echo 'console.log(1)' >"$work/frontend/dist/assets/index-abc123.js"
cp "$root/$dockerfile" "$work/Dockerfile"
docker build -q --load -t "$tag" "$work" >/dev/null
docker run -d --name "$front" -e BACKEND_HOST=127.0.0.1 -e BACKEND_PORT=8080 "$tag" >/dev/null

headers() {
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		out="$(docker exec "$front" wget -S -qO /dev/null "http://127.0.0.1$1" 2>&1 || true)"
		case "$out" in *"HTTP/"*) printf '%s' "$out" | grep -i 'cache-control' || true; return ;; esac
		sleep 1
	done
}

status=0
for path in / /index.html /packages /package/go/example.com/mod/v1.0.0; do
	cc="$(headers "$path")"
	case "$cc" in
	*no-cache*) echo "ok: $path is revalidated" ;;
	*) echo "FAIL: $path Cache-Control [$cc], want no-cache"; status=1 ;;
	esac
done
cc="$(headers /assets/index-abc123.js)"
case "$cc" in
*immutable*) echo "ok: hashed asset is immutable" ;;
*) echo "FAIL: asset Cache-Control [$cc], want immutable"; status=1 ;;
esac
exit "$status"
