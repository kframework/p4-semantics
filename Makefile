KOMPILE=kompile --debug -ccopt -g
P4_DIR=src/p4
STF_DIR=src/stf
CLI_DIR=src/cli

all: cli

$(P4_DIR)/p4-semantics-kompiled: $(wildcard $(P4_DIR)/*.k) $(wildcard $(P4_DIR)/syntax/*.k)
	$(KOMPILE) $(P4_DIR)/p4-semantics.k --syntax-module P4-SYNTAX --main-module P4-SEMANTICS;

$(CLI_DIR)/cli-semantics-kompiled: $(wildcard $(CLI_DIR)/*.k) $(wildcard $(P4_DIR)/*.k) $(wildcard $(P4_DIR)/syntax/*.k)
	$(KOMPILE) $(CLI_DIR)/cli.k --syntax-module CLI-SYNTAX --main-module CLI-SEMANTICS

p4: $(P4_DIR)/p4-semantics-kompiled
cli: $(CLI_DIR)/cli-semantics-kompiled


clean:
	rm -rf $(CLI_DIR)/cli-semantics-kompiled $(P4_DIR)/p4-semantics-kompiled

