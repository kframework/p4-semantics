import argparse
import os
import sys

#krun --directory src/stf  -cPGM="`cat test/semantics/basic_routing/basic_routing.p4`" -pPGM="kast --directory src/ -o kore" -cSTF="`cat src/x.stf`" -pSTF="kast -s STFPgm -m STF-TEST-SYNTAX --directory src/stf -o kore"  --save-temps --verbose
def run_cli(args):
    command = """krun                                                 \\
     --directory src/cli                                                \\
     -cPGM="`cat {p4}`"                                                 \\
     -pPGM="kast -s P4Program -m P4-SYNTAX --directory src/cli -o kore" \\
     -cCLI="`cat {cli}`"                                                \\
     -pCLI="kast -s CLIPgm -m CLI-SYNTAX --directory src/cli -o kore"   \\
     {debugger} {args}                                                 \\
      """
    command = command.format(
        p4=args.p4,
        cli=args.cli,
        debugger="--debugger" if args.debugger else "",
        args=args.krun_args
    )
    print(command, file=sys.stderr)
    os.system(command)

def search_cli(args):
    command = """krun                                                 \\
     --directory src/cli                                                \\
     -cPGM="`cat {p4}`"                                                 \\
     -pPGM="kast -s P4Program -m P4-SYNTAX --directory src/cli -o kore" \\
     -cCLI="`cat {cli}`"                                                \\
     -pCLI="kast -s CLIPgm -m CLI-SYMBOLIC-SYNTAX --directory src/cli -o kore"   \\
      {args}                                                 \\
      """
    command = command.format(
        p4=args.p4,
        cli=args.cli,
        args=args.krun_args
    )
    print(command, file=sys.stderr)
    os.system(command)

def p4assert(args):
    command = """krun                                                 \\
     --directory src/p4assert                                                \\
     -cPGM="`cat {p4}`"                                                 \\
     -pPGM="kast -s P4Program -m P4ASSERT-SYNTAX --directory src/p4assert -o kore" \\
     -cCLI="`cat {cli}`"                                                \\
     -pCLI="kast -s CLIPgm -m CLI-SYMBOLIC-SYNTAX --directory src/p4assert -o kore"   \\
      {args}                                                 \\
      """
    command = command.format(
        p4=args.p4,
        cli=args.cli,
        args=args.krun_args
    )
    print(command, file=sys.stderr)
    os.system(command)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='p4k')
    parser.add_argument('--krun-args', type=str, help='Additional arguments to be passed to krun', default="--verbose --save-temps")
    subparsers = parser.add_subparsers(dest='command')

    parser_run_cli = subparsers.add_parser('run-cli', help='Runs P4 code with CLI file')
    parser_run_cli.add_argument('p4', type=str, help='P4 file')
    parser_run_cli.add_argument('cli', type=str, help='CLI file')
    parser_run_cli.add_argument('--debugger', action='store_true', help='Run in debugger mode', default=False)

    parser_search_cli = subparsers.add_parser('search-cli', help='Symbolically run P4 code with CLI file')
    parser_search_cli.add_argument('p4', type=str, help='P4 file')
    parser_search_cli.add_argument('cli', type=str, help='CLI file')

    parser_p4assert = subparsers.add_parser('p4assert', help='P4 assert')
    parser_p4assert.add_argument('p4', type=str, help='P4 file')
    parser_p4assert.add_argument('cli', type=str, help='CLI file')



    args = parser.parse_args()
    if args.command == 'run-cli':
        run_cli(args)
    if args.command == 'search-cli':
        search_cli(args)
    if args.command == 'p4assert':
        p4assert(args)



