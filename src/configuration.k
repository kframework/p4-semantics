require "syntax/p4-syntax.k"



module CONFIGURATION
imports P4-COMMON

syntax KItem ::= "@exec"

configuration
<T>
    <k> $PGM:P4Program ~> @exec </k>

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



rule <k> (H:HeaderTypeDeclaration => .K) ... </k> //<headers> (.Bag => <header> H </header>) </headers>

endmodule