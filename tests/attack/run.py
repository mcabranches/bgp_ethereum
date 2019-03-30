#!/usr/bin/env python

import os
from argparse import ArgumentParser

parser = ArgumentParser("Connect to a mininet node and run a command") 
parser.add_argument('--node',
    help="The node's name (e.g., h1, h2, etc.)")
parser.add_argument('--cmd', default='ifconfig',
    nargs="+",
    help="Command to run inside node.")
FLAGS = parser.parse_args()

def main():
    cmd = ' '.join(FLAGS.cmd)
    node = FLAGS.node
    os.system("docker exec -ti mn.%s bash -c '%s'" % (node, cmd))

if __name__ == '__main__':
    main()
