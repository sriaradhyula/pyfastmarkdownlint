#!/usr/bin/env python3

"""Fast Markdown Python Linter:

This script lints markdown files, it can be executed as a standalone script
or can also be imported as a module.

Uses markdownlint as reference for markdown linting rules.

Reference Rules: https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md
"""

import argparse
import logging
import os
import sys
from threading import Thread
from queue import Queue

# Set logging variabels
log = logging.getLogger()

loglevels = {
  "http": logging.DEBUG,
  "debug": logging.DEBUG,
  "info": logging.INFO,
  "warning": logging.WARNING,
  "error": logging.ERROR,
  "critical": logging.CRITICAL
}

# Global variables
MARKDOWN_MAX_LINE_LENGTH = os.getenv("MARKDOWN_MAX_LINE_LENGTH", 80)
CONSECUTIVE_BLANK_LINES = 0


def _set_log_level(loglevel_str="info"):
  """
  Creates a logging stream handler to stdout,
  sets the logging format and also sets the
  default logging level if not specified

  Parameters
  ----------
  loglevel_str : str
      Log level string.
      Default: "info"
  """
  log.setLevel(loglevels[loglevel_str])
  handler = logging.StreamHandler(sys.stdout)
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  handler.setFormatter(formatter)
  log.addHandler(handler)


class ThreadPool:
  """
  Pool of threads in a queue

  Attributes
  ----------
  num_threads : number threads in the queue

  Methods
  -------
  add_task(self, func, *args, **kargs):
      Add task to queue
  wait_completion(self):
      Wait for completion of all tasks in the queue
  """
  def __init__(self, num_threads):
    self.tasks = Queue(num_threads)
    for _ in range(num_threads):
      Worker(self.tasks)

  def add_task(self, func, *args, **kargs):
    """Add a task to the queue"""
    self.tasks.put((func, args, kargs))

  def wait_completion(self):
    """Wait for completion of all tasks in the queue"""
    self.tasks.join()


class Worker(Thread):
  """
  Worker thread executing tasks from a given tasks queue

  Attributes
  ----------
  tasks : tasks to execute

  Methods
  -------
  run(self):
      main loop that executes the tasks until completion
  """
  def __init__(self, tasks):
    Thread.__init__(self)
    self.tasks = tasks
    self.daemon = True
    self.start()

  def run(self):
    """main loop that executes the tasks until completion"""
    while True:
      func, args, kargs = self.tasks.get()
      try:
        func(*args, **kargs)
      except Exception as e:
        logging.info(e)
      finally:
        self.tasks.task_done()


def md009_trailing_whitespace(md_rule_name, line, line_number):
  """Check for trailing whitespace

  Reference: https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md#md009---trailing-spaces

  Output: Prints the violation string

  Parameters
  ----------
  md_rule_name : str
      Markdown Rule Name as described in https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md
  line : str
      Line string under review for any potential violations
  line_number: int
      Line number in the markdown file being scanned for violations
  """
  line_len = len(line)
  last_character = line[-1]
  log.debug(f"Line Length:{line_len}, last character: _{last_character}_")

  if ' ' in last_character:
    print(f"Rule: {md_rule_name}, Line#: {line_number}: {line[:10]}... Voilation: Trailing spaces")


def md013_line_length(md_rule_name, line, line_number):
  """Check line length of each line

  Reference: https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md

  Output: Prints the violation string

  Parameters
  ----------
  md_rule_name : str
      Markdown Rule Name as described in https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md
  line : str
      Line string under review for any potential violations
  line_number: int
      Line number in the markdown file being scanned for violations
  """
  line_len = len(line)
  log.debug(f"Line Length:{line_len}")

  if line_len > MARKDOWN_MAX_LINE_LENGTH:
    print(f"Rule: {md_rule_name}, Line#: {line_number}: {line[:10]}... Voilation: Curent line length {line_len} exceeds max {MARKDOWN_MAX_LINE_LENGTH}")


def md012_no_multiple_blanks(md_rule_name, line, line_number):
    """Check no multiple blank lines

    Reference: https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md

    Output: Prints the violation string

    Parameters
    ----------
    md_rule_name : str
        Markdown Rule Name as described in https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md
    line : str
        Line string under review for any potential violations
    line_number: int
        Line number in the markdown file being scanned for violations
    """
    if CONSECUTIVE_BLANK_LINES > 1:
      print(f"Rule: {md_rule_name}, Line#: {line_number}: Voilation: Multiple consecutive blank lines")


def md041_first_line_top_level_header(md_rule_name, line, line_number):
    """Check if the first line is a top level header

    Reference: https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md#md041---first-line-in-file-should-be-a-top-level-header

    Output: Prints the violation string

    Parameters
    ----------
    md_rule_name : str
        Markdown Rule Name as described in https://github.com/markdownlint/markdownlint/blob/main/docs/RULES.md
    line : str
        Line string under review for any potential violations
    line_number: int
        Line number in the markdown file being scanned for violations
    """
    line_len = len(line)
    first_character = line[0]
    log.debug(f"Line Length:{line_len}, first character: _{first_character}_")

    if '#' not in first_character:
      print(f"Rule: {md_rule_name}, Line#: {line_number}: {line[:10]}... Voilation: Missing top level header")


md_lint_rules = {
                  "md009": md009_trailing_whitespace,
                  "md013": md013_line_length,
                  "md041": md041_first_line_top_level_header,
                }

def check_for_lint(line, line_number):
  """
  Checks for multiple lint violiations in parallel per line

  Parameters
  ----------
  line : str
      Line string under review for any potential violations
  line_number: int
      Line number in the markdown file being scanned for violations
  """
  md_lint_rules_len = len(md_lint_rules)

  # Create a threadpool per line
  pool = ThreadPool(md_lint_rules_len)
  rule_count = 0

  # Queue each markdown violation check as a task to threadpool
  for md_rule_name, md_rule_func in md_lint_rules.items():
      log.debug("-"*80)
      log.debug(f"Line#: {line_number}")
      log.debug(f"Rule Count: {rule_count}")
      # markdown rule #41 is a special case, only checked for first line
      if line_number == 1 and "md041" in md_rule_name:
        pool.add_task(md_rule_func, md_rule_name, line, line_number)
      if "md041" not in md_rule_name:
        pool.add_task(md_rule_func, md_rule_name, line, line_number)
      rule_count = rule_count + 1
      log.debug("-"*80)

  # Wait for all tasks queued up previously to complete per line
  pool.wait_completion()
  log.debug("*"*80)
  log.debug(f"Evaulated rules: {rule_count}")
  log.debug("*"*80)


def main():
  # Setup commandline argumemts for the standalone script
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('input_file',
                      type=str,
                      help="Specifiy the markdown file to lint")
  parser.add_argument( '--loglevel',
                      dest='loglevel',
                      help='Set loglevel')
  args = parser.parse_args()
  if args.loglevel:
      _set_log_level(args.loglevel)

  # Read the input markdown file and create a list of lines
  input_file_data = open(args.input_file, "r").readlines()

  # Start line_number counter from 1 as it is more human readable
  line_number = 1
  global CONSECUTIVE_BLANK_LINES
  for each_line in input_file_data:
    # Strip '\n' newline from each line to detect trailing spaces
    each_line_stripped = each_line.strip('\n')

    if len(each_line_stripped) > 0:
      # For a non-blank line check for multiple violations
      # Reset blank line counter if non-blank line is found
      CONSECUTIVE_BLANK_LINES = 0
      check_for_lint(each_line_stripped, line_number)
    else:
      # Special case that checks for multiple blank lines
      CONSECUTIVE_BLANK_LINES = CONSECUTIVE_BLANK_LINES + 1
      md012_no_multiple_blanks('md012', each_line_stripped, line_number)
    line_number = line_number + 1


if __name__ == "__main__":
    main()
