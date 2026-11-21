.PHONY: help test lint sbd-lint sbd-test sbd-package pt-lint pt-test pt-package package

DIST_DIR := dist

SBD_DIR         := secure-by-design
SBD_VERSION     := $(shell python3 -c "import json; print(json.load(open('$(SBD_DIR)/.claude-plugin/plugin.json'))['version'])" 2>/dev/null || echo "unknown")
SBD_PLUGIN_FILE := $(DIST_DIR)/secure-by-design-v$(SBD_VERSION).plugin
SBD_SHELL       := $(SBD_DIR)/skills/sbd-security-gate/scripts/run_gate.sh $(SBD_DIR)/scripts/install-into-project.sh \
                   $(SBD_DIR)/tests/selftest_gate.sh $(SBD_DIR)/tests/selftest_install.sh

PT_DIR         := pentest
PT_VERSION     := $(shell python3 -c "import json; print(json.load(open('$(PT_DIR)/.claude-plugin/plugin.json'))['version'])" 2>/dev/null || echo "unknown")
PT_PLUGIN_FILE := $(DIST_DIR)/pentest-v$(PT_VERSION).plugin
PT_SHELL       := $(PT_DIR)/scripts/install-into-project.sh $(PT_DIR)/tests/selftest_install.sh

help:
	@echo "Targets:"
	@echo "  make lint         lint di entrambi i plugin"
	@echo "  make test         self-test di entrambi i plugin"
	@echo "  make package      builda $(SBD_PLUGIN_FILE) e $(PT_PLUGIN_FILE)"
	@echo "  make sbd-lint | sbd-test | sbd-package   solo secure-by-design"
	@echo "  make pt-lint  | pt-test  | pt-package    solo pentest"

lint: sbd-lint pt-lint
test: sbd-test pt-test
package: sbd-package pt-package

# --- secure-by-design -------------------------------------------------------

sbd-lint:
	@echo "[sbd-lint] skill, riferimenti e ID delle regole..."
	@python3 $(SBD_DIR)/tests/lint_skills.py
	@if command -v shellcheck >/dev/null 2>&1; then \
	  echo "[sbd-lint] shellcheck..."; shellcheck -S warning $(SBD_SHELL); \
	else \
	  echo "[sbd-lint] shellcheck non installato — lint shell saltato"; \
	fi

sbd-test:
	@echo "[sbd-test] scanner di pattern..."
	@python3 $(SBD_DIR)/tests/selftest_patterns.py
	@echo "[sbd-test] security gate..."
	@bash $(SBD_DIR)/tests/selftest_gate.sh
	@echo "[sbd-test] installer..."
	@bash $(SBD_DIR)/tests/selftest_install.sh
	@echo "[sbd-test] scansione del plugin con il proprio scanner..."
	@python3 $(SBD_DIR)/skills/sbd-security-gate/scripts/sbd_patterns.py $(SBD_DIR)

sbd-package: sbd-lint
	@mkdir -p $(DIST_DIR)
	@cd $(SBD_DIR) && zip -r -q -FS ../$(SBD_PLUGIN_FILE) .claude-plugin skills templates scripts README.md \
	    -x "*.DS_Store" "*/__pycache__/*" "*.pyc"
	@echo "✔ $(SBD_PLUGIN_FILE)"

# --- pentest ----------------------------------------------------------------

pt-lint:
	@echo "[pt-lint] skill, riferimenti e ID delle regole..."
	@python3 $(PT_DIR)/tests/lint_skills.py
	@if command -v shellcheck >/dev/null 2>&1; then \
	  echo "[pt-lint] shellcheck..."; shellcheck -S warning $(PT_SHELL); \
	else \
	  echo "[pt-lint] shellcheck non installato — lint shell saltato"; \
	fi

pt-test:
	@echo "[pt-test] guardrail scope_check..."
	@python3 $(PT_DIR)/tests/selftest_scope.py
	@echo "[pt-test] installer..."
	@bash $(PT_DIR)/tests/selftest_install.sh

pt-package: pt-lint
	@mkdir -p $(DIST_DIR)
	@cd $(PT_DIR) && zip -r -q -FS ../$(PT_PLUGIN_FILE) .claude-plugin skills templates scripts README.md \
	    -x "*.DS_Store" "*/__pycache__/*" "*.pyc"
	@echo "✔ $(PT_PLUGIN_FILE)"
