KOMPILE=kompile --debug -ccopt -g
P4_DIR=src/p4
STF_DIR=src/stf
CLI_DIR=src/cli
NETWORK_DIR=src/network

all: cli

$(P4_DIR)/p4-semantics-kompiled: $(wildcard $(P4_DIR)/*.k) $(wildcard $(P4_DIR)/syntax/*.k)
	$(KOMPILE) $(P4_DIR)/p4-semantics.k --syntax-module P4-SYNTAX --main-module P4-SEMANTICS;

$(CLI_DIR)/cli-semantics-kompiled: $(wildcard $(CLI_DIR)/*.k) $(wildcard $(P4_DIR)/*.k) $(wildcard $(P4_DIR)/syntax/*.k)
	$(KOMPILE) $(CLI_DIR)/cli.k --syntax-module CLI-SYNTAX --main-module CLI-SEMANTICS

$(CLI_DIR)/cli-symbolic-semantics-kompiled: $(wildcard $(CLI_DIR)/*.k) $(wildcard $(P4_DIR)/*.k) $(wildcard $(P4_DIR)/syntax/*.k)
	kompile --backend haskell $(CLI_DIR)/cli-symbolic.k --syntax-module CLI-SYMBOLIC-SYNTAX --main-module CLI-SYMBOLIC-SEMANTICS

$(NETWORK_DIR)/network-semantics-kompiled: $(wildcard $(NETWORK_DIR)/*.k) $(wildcard $(P4_DIR)/*.k) $(wildcard $(P4_DIR)/syntax/*.k)
	$(KOMPILE) $(NETWORK_DIR)/network.k --syntax-module NETWORK-SYNTAX --main-module NETWORK-SEMANTICS

p4: $(P4_DIR)/p4-semantics-kompiled
cli: $(CLI_DIR)/cli-semantics-kompiled
cli-symbolic: $(CLI_DIR)/cli-symbolic-semantics-kompiled
network: $(NETWORK_DIR)/network-semantics-kompiled


clean:
	rm -rf $(CLI_DIR)/cli-semantics-kompiled $(P4_DIR)/p4-semantics-kompiled

krun                                                   \
     --directory src/cli                                                \
     test/semantics/basic_routing/basic_routing.p4 \
     -pPGM="kast -s P4Program -m P4-SYNTAX --directory src/cli -o kore" \
     -cCLI="@sympacket"                                                \
     -pCLI="kast -s CLIPgm -m CLI-SYMBOLIC-SYNTAX --directory src/cli -o kore"   \
      --verbose  --save-temps                                               \
