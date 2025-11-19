.PHONY: run test clean generate wire generate_api generate_responses show_docs postman

run:
	go run ./cmd/server

test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf coverage.out coverage.html generated/api
	find . -name "*.db" -type f -delete
	find . -name "*.db-shm" -type f -delete
	find . -name "*.db-wal" -type f -delete

generate: generate_api wire
	@echo "All code generation completed successfully"

generate_api: api/openapi.yml
	@echo "Generating API code from OpenAPI spec..."
	@mkdir -p generated/api
	@echo "  - Bundling OpenAPI spec (resolving \$ref)..."
	@which redocly > /dev/null 2>&1 && \
	 (redocly bundle api/openapi.yml -o api/openapi-bundled.yml > /dev/null 2>&1 && \
	  echo "  - Generating types (including response types)..." && \
	  oapi-codegen --package api -generate types api/openapi-bundled.yml > generated/api/api-types.gen.go && \
	  echo "  - Generating server code (gin, spec)..." && \
	  oapi-codegen --package api -generate gin,spec api/openapi-bundled.yml > generated/api/api-server.gen.go && \
	  rm -f api/openapi-bundled.yml) || \
	 (echo "  - Warning: redocly not found, generating without bundle (may miss some types)..." && \
	  echo "  - Generating types (including response types)..." && \
	  oapi-codegen --package api -generate types $< > generated/api/api-types.gen.go && \
	  echo "  - Generating server code (gin, spec)..." && \
	  oapi-codegen --package api -generate gin,spec $< > generated/api/api-server.gen.go)
	@echo "✓ API code generated successfully"

wire:
	@echo "Generating Wire dependency injection code..."
	@wire ./internal/composers
	@echo "✓ Wire code generated"

show_docs:
	@echo "=========================================="
	@echo "OpenAPI Documentation"
	@echo "=========================================="
	@echo ""
	@echo "Option 1: Using Redocly (Recommended)"
	@echo "  Install: npm install -g @redocly/cli"
	@echo "  Run:     redocly preview-docs api/openapi.yml"
	@echo ""
	@echo "Option 2: Using Swagger UI"
	@echo "  Install: npm install -g swagger-ui-serve"
	@echo "  Run:     swagger-ui-serve api/openapi.yml"
	@echo ""
	@echo "Option 3: Using Docker"
	@echo "  Run:     docker run -p 8080:8080 -e SWAGGER_JSON=/api/openapi.yml -v \$$(pwd)/api:/api swaggerapi/swagger-ui"
	@echo ""
	@echo "Option 4: Online Viewer"
	@echo "  Visit:   https://editor.swagger.io/"
	@echo "  Upload: api/openapi.yml"
	@echo ""
	@echo "Trying to start with Redocly..."
	@which redocly > /dev/null 2>&1 && \
	 (echo "Starting Redocly preview server on http://localhost:8081..." && \
	  redocly preview-docs api/openapi.yml --port 8081) || \
	 (echo "" && \
	  echo "Redocly not found. Please install it:" && \
	  echo "  npm install -g @redocly/cli" && \
	  echo "" && \
	  echo "Or use one of the alternative options above.")

postman:
	@echo "Building Postman collection from OpenAPI spec..."
	@./bin/build-postman.sh

