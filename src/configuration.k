require "syntax/p4-syntax.k"



module CONFIGURATION
imports P4-COMMON


syntax KItem ::= "@exec"
syntax Kitem ::= "@splitDeclarations" "(" P4Declarations ")"

configuration
<T>
    <k>  $PGM:P4Program ~> @exec </k>

    <tables>
        <table multiplicity="*">
            .K
        </table>
    </tables>

    <headers>
        <header multiplicity="*">
            .K
        </header>
    </headers>

    <instances>
        .K
    </instances>

    <parser>
        .K
    </parser>
</T>


// putting decralarions into configuration cells

rule <k> (P:P4Declarations => @splitDeclarations(P)) ... </k> [structural]

rule <k> @splitDeclarations((H:HeaderTypeDeclaration Rest:P4Declarations) => Rest) ... </k>
        <headers> ... (.Bag => <header> H </header>) ... </headers> [structural]


rule <k> @splitDeclarations(.P4Declarations) => . ... </k> [structural]




/*
rule <k> (H:HeaderTypeDeclaration Rest:P4Declarations) => Rest ... </k> <headers> ... (.Bag => <header> H </header>) ... </headers>
rule <k> (.P4Declarations => .) ... </k>
*/
endmodule