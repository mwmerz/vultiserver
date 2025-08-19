generate-demo:
	yes | rm -rf demo/generated/* && cd demo/app && npm i && REACT_APP_VULTISIGNER_BASE_URL="http://127.0.0.1:8080/" REACT_APP_VULTISIG_RELAYER_URL="https://api.vultisig.com/" REACT_APP_MINIMUM_DEVICES=2  REACT_APP_VULTISIGNER_USER="username" REACT_APP_VULTISIGNER_PASSWORD="password"  npm run build && mv build/* ../generated

# Generate OpenAPI/Swagger documentation
swagger:
	swag init -g cmd/api/main.go --output docs --parseDependency --parseInternal

# Generate TypeScript types from Go structs
typescript:
	./scripts/generate-types.sh

# Generate both OpenAPI and TypeScript
generate: swagger typescript
	@echo "✅ Generated OpenAPI spec in ./docs"
	@echo "✅ Generated TypeScript types in ./generated/types.ts"

# Clean generated files
clean-generated:
	rm -rf docs/ generated/

# Serve Swagger UI (requires server to be running)
swagger-ui:
	@echo "Swagger UI will be available at http://localhost:8080/swagger/index.html"
	@echo "Make sure the server is running first!"

.PHONY: generate-demo swagger typescript generate clean-generated swagger-ui
