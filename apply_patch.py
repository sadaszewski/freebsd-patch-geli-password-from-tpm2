from argparse import ArgumentParser


def create_parser():
  parser = ArgumentParser()
  parser.add_argument('--target-dir', type=str, default='/usr/src')
  return parser


def main():
  parser = create_parser()
  args = parser.parse_args()
  
  
if __name__ == '__main__':
  main()
  
