src/p4-semantics-kompiled: $(wildcard src/*.k) $(wildcard src/syntax/*.k)
	kompile src/p4-semantics.k --syntax-module P4-SYNTAX --main-module P4-SEMANTICS;

src/stf/stf-semantics-kompiled: src/p4-semantics-kompiled $(wildcard src/stf/*.k)
	kompile src/stf/stf-test.k --syntax-module STF-TEST-SYNTAX --main-module STF-TEST-SEMANTICS

stf: src/stf/stf-semantics-kompiled
p4: src/p4-semantics-kompiled
clean:
	rm -rf src/stf/stf-semantics-kompiled src/p4-semantics-kompiled

