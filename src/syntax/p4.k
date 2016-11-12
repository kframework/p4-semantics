require "value.k"
require "table.k"
require "stateful.k"
require "parser.k"
require "header.k"
require "control.k"

// based on P4 Language Spec Version 1.0.3 Nov. 2016

module P4

endmodule

module P4-SYNTAX
    imports VALUE-SYNTAX
    imports HEADER-SYNTAX
    imports STATEFUL-SYNTAX
    imports CHECKSUM-SYNTAX
    imports PARSER-SYNTAX
    imports PARSER-EXCEPTION-SYNTAX
    imports ACTION-SYNTAX
    imports ACTION-PROFILE-SYNTAX
    imports TABLE-SYNTAX
    imports CONTROL-SYNTAX

    syntax P4Program ::= P4Declarations

    syntax P4Declarations ::= NeList{P4Declaration,""}  [klabel('P4Declarations)]

    syntax P4Declaration ::=
                  HeaderTypeDeclaration
                | InstanceDeclaration
                | FieldListDeclaration
                | FieldListCalculationDeclaration
                | CalculatedFieldDeclaration
                | ValueSetDeclaration
                | ParserFunctionDeclaration
                | ParserExceptionDeclaration
                | CounterDeclaration
                | MeterDeclaration
                | RegisterDeclaration
                | ActionFunctionDeclaration
                | ActionProfileDeclaration
                | ActionSelectorDeclaration
                | TableDeclaration
                | ControlFunctionDeclaration


endmodule