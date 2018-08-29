import argparse
import sys

from .rockyrainbow import RainbowScheduler

if __name__ == "__main__":
    wordlists = None

    parser = argparse.ArgumentParser(description="RockyRainbow - make rainbow tables form password lists")
    parser.add_argument("wordlists", metavar="WORDLISTS", type=str, nargs='+',
                        help="Wordlists to Rainbowfy")
    parser.add_argument("--hash", metavar="hash_function", help="Hash function to use", type=str, required=False,
                        dest="hash_function")
    args = parser.parse_args()

    if len(args.wordlists) == 0:
        argparse.usage()
        sys.exit(1)

    RainbowScheduler(args.wordlists, args.hash_function)
