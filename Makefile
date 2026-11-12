.PHONY: test smoke build up
test:        ## backend tests (needs MongoDB on :27017 and Redis on :6379)
	cd backend && pytest -q
smoke:       ## real-process smoke tests (Celery worker; Next.js + API)
	cd backend && python scripts/smoke_celery.py && python scripts/smoke_stack.py
build:
	cd frontend && npm ci && BACKEND_URL=http://127.0.0.1:8000 npm run build
up:
	docker compose up --build -d
